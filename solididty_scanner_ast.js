const parser = require('solidity-parser-antlr');

// ========== УТИЛИТЫ ==========
function parseVersionFromPragma(pragma) {
    if (!pragma) return null;
    const match = pragma.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
    if (!match) return null;
    return [
        parseInt(match[1]),
        parseInt(match[2]),
        match[3] ? parseInt(match[3]) : 0
    ];
}

function versionGe(v, target = [0, 8, 0]) {
    if (!v) return false;
    for (let i = 0; i < 3; i++) {
        if (v[i] > target[i]) return true;
        if (v[i] < target[i]) return false;
    }
    return true;
}

// Утилита для получения исходного кода по диапазону
function getSourceSnippet(sourceCode, start, end, maxLength = 1000) {
    const snippet = sourceCode.substring(start, end);
    if (snippet.length > maxLength) {
        return snippet.substring(0, maxLength) + '...';
    }
    return snippet;
}

// ========== УЛУЧШЕННЫЙ ПАРСЕР (ПРОДУКЦИОННЫЙ) ==========
class EnhancedParser {
    static findPragma(ast) {
        let pragma = null;
        parser.visit(ast, {
            PragmaDirective: function(node) {
                if (node.name === 'solidity') {
                    pragma = node.value;
                }
            }
        });
        return pragma;
    }

    static extractFunctions(ast, sourceCode) {
        const functions = [];
        
        parser.visit(ast, {
            FunctionDefinition: function(node) {
                // Извлекаем имя функции (конструктор может не иметь имени)
                const funcName = node.name || '<constructor>';
                
                // Извлекаем сигнатуру из исходного кода
                const signatureStart = node.range[0];
                const bodyStart = node.body ? node.body.range[0] : node.range[1];
                const signature = sourceCode.substring(signatureStart, bodyStart).trim();
                
                // Извлекаем тело функции
                let body = '';
                if (node.body) {
                    body = getSourceSnippet(sourceCode, node.body.range[0], node.body.range[1]);
                }
                
                functions.push({
                    name: funcName,
                    signature: signature,
                    body: body,
                    astNode: node,
                    range: node.range,
                    bodyRange: node.body ? node.body.range : null
                });
            }
        });
        
        return functions;
    }
}

// ========== ПРОДУКЦИОННЫЕ ПРОВЕРКИ PRO MAX ==========
class ProSecurityChecks {
    
    static isLibraryOrViewFunction(func) {
        const node = func.astNode;
        return node.stateMutability === 'view' || node.stateMutability === 'pure';
    }

    static hasReentrancyGuard(node) {
        if (!node.modifiers) return false;
        const guardModifiers = ['nonreentrant', 'reentrancyguard', 'locked', 'mutex', 'nolock'];
        return node.modifiers.some(mod => 
            guardModifiers.some(guard => mod.name.toLowerCase().includes(guard))
        );
    }

    static hasAccessControl(node, sourceCode) {
        // Проверяем наличие модификаторов доступа
        if (node.modifiers) {
            const accessModifiers = ['onlyowner', 'onlyadmin', 'onlyrole', 'restricted', 'auth'];
            if (node.modifiers.some(mod => accessModifiers.includes(mod.name.toLowerCase()))) {
                return true;
            }
        }
        
        // Проверяем ручные проверки msg.sender в теле функции
        let hasManualCheck = false;
        if (node.body) {
            parser.visit(node.body, {
                FunctionCall: function(n) {
                    if (n.expression.name === 'require' || n.expression.name === 'assert') {
                        const checkText = sourceCode.substring(n.range[0], n.range[1]).toLowerCase();
                        if (checkText.includes('msg.sender') && 
                            (checkText.includes('owner') || checkText.includes('admin'))) {
                            hasManualCheck = true;
                        }
                    }
                }
            });
        }
        
        return hasManualCheck;
    }

    // ---------- 1. REENTRANCY (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkReentrancy(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (this.hasReentrancyGuard(node)) return findings;
        
        const externalCalls = [];
        const stateChanges = [];
        
        // Собираем ВСЕ внешние вызовы и изменения состояния
        parser.visit(node.body, {
            // Внешние вызовы (call, transfer, send)
            FunctionCall: function(n) {
                if (n.expression.type === 'MemberAccess') {
                    const ma = n.expression;
                    const callText = sourceCode.substring(n.range[0], n.range[1]);
                    
                    // Проверяем все виды опасных вызовов
                    if (ma.memberName === 'call' || 
                        ma.memberName === 'transfer' || 
                        ma.memberName === 'send') {
                        
                        externalCalls.push({
                            node: n,
                            text: callText,
                            pos: n.range[0],
                            isValueTransfer: callText.includes('value:') || 
                                           ma.memberName === 'transfer' || 
                                           ma.memberName === 'send'
                        });
                    }
                }
            },
            
            // Изменения состояний (балансов, totalsupply и т.д.)
            Assignment: function(n) {
                const assignText = sourceCode.substring(n.range[0], n.range[1]).toLowerCase();
                const leftText = sourceCode.substring(n.left.range[0], n.left.range[1]).toLowerCase();
                
                if (leftText.includes('balance') || 
                    leftText.includes('total') || 
                    leftText.includes('supply') ||
                    leftText.includes('_balances') ||
                    leftText.includes('.balance')) {
                    
                    stateChanges.push({
                        node: n,
                        text: assignText,
                        pos: n.range[0]
                    });
                }
            },
            
            // Инкременты/декременты (++, --)
            UnaryOperation: function(n) {
                if (n.isPrefix || n.isPostfix) {
                    const opText = sourceCode.substring(n.range[0], n.range[1]).toLowerCase();
                    if (opText.includes('balance') || opText.includes('total')) {
                        stateChanges.push({
                            node: n,
                            text: opText,
                            pos: n.range[0]
                        });
                    }
                }
            }
        });
        
        // Проверяем классическую уязвимость CEI (Checks-Effects-Interactions)
        for (const call of externalCalls) {
            for (const state of stateChanges) {
                if (call.pos < state.pos) {
                    // Проверяем, есть ли проверка между call и state change
                    const betweenCode = sourceCode.substring(call.pos, state.pos);
                    if (!betweenCode.includes('require(') && 
                        !betweenCode.includes('assert(') && 
                        !betweenCode.includes('if (') &&
                        !betweenCode.includes('revert')) {
                        
                        findings.push(`REENTRANCY: External call at line ${this.getLineNumber(call.pos, sourceCode)} before state update - violates CEI pattern`);
                    }
                }
            }
            
            // Проверяем unchecked calls
            if (call.isValueTransfer) {
                let hasSuccessCheck = false;
                let current = call.node;
                
                // Ищем проверку успеха после вызова
                while (current.parent) {
                    current = current.parent;
                    if (current.type === 'IfStatement' || 
                        (current.type === 'FunctionCall' && 
                         (current.expression.name === 'require' || 
                          current.expression.name === 'assert'))) {
                        
                        const checkText = sourceCode.substring(current.range[0], current.range[1]).toLowerCase();
                        if (checkText.includes('success') || checkText.includes('ok')) {
                            hasSuccessCheck = true;
                            break;
                        }
                    }
                }
                
                if (!hasSuccessCheck) {
                    findings.push(`UNCHECKED_CALL: Value transfer without success check: ${call.text.substring(0, 50)}...`);
                }
            }
        }
        
        return findings;
    }

    // ---------- 2. OVERFLOW/UNDERFLOW (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkOverflow(func, pragma, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        const version = parseVersionFromPragma(pragma);
        const builtinSafe = versionGe(version, [0, 8, 0]);
        
        // Ищем unchecked блоки
        parser.visit(node.body, {
            UncheckedStatement: function(n) {
                // Проверяем, есть ли внутри арифметические операции
                let hasArithmetic = false;
                parser.visit(n.body, {
                    BinaryOperation: function(binOp) {
                        if (['+', '-', '*', '/', '**'].includes(binOp.operator)) {
                            hasArithmetic = true;
                        }
                    },
                    Assignment: function(assign) {
                        if (assign.operator && ['+=', '-=', '*=', '/=', '**='].includes(assign.operator)) {
                            hasArithmetic = true;
                        }
                    }
                });
                
                if (hasArithmetic) {
                    findings.push(`OVERFLOW: 'unchecked' block contains arithmetic operations at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                }
            }
        });
        
        // Для версий < 0.8.0 проверяем арифметику без SafeMath
        if (!builtinSafe) {
            let hasUnsafeArithmetic = false;
            let usesSafeMath = false;
            
            // Проверяем использование SafeMath
            parser.visit(func.astNode, {
                UsingForDeclaration: function(n) {
                    if (n.libraryName && n.libraryName.toLowerCase().includes('safemath')) {
                        usesSafeMath = true;
                    }
                }
            });
            
            // Проверяем арифметические операции
            parser.visit(node.body, {
                BinaryOperation: function(n) {
                    if (['+', '-', '*', '/', '**'].includes(n.operator)) {
                        hasUnsafeArithmetic = true;
                    }
                },
                Assignment: function(n) {
                    if (n.operator && ['+=', '-=', '*=', '/=', '**='].includes(n.operator)) {
                        hasUnsafeArithmetic = true;
                    }
                }
            });
            
            if (hasUnsafeArithmetic && !usesSafeMath) {
                findings.push("OVERFLOW: Arithmetic operations in Solidity < 0.8.0 without SafeMath library");
            }
        }
        
        // Проверяем маленькие типы (uint8, uint16, uint32)
        parser.visit(node, {
            VariableDeclaration: function(n) {
                if (n.typeName && n.typeName.name) {
                    const typeName = n.typeName.name.toLowerCase();
                    if (typeName.includes('uint8') || typeName.includes('uint16') || typeName.includes('uint32')) {
                        // Проверяем, используется ли эта переменная в арифметике
                        let usedInArithmetic = false;
                        parser.visit(node.body, {
                            Identifier: function(id) {
                                if (id.name === n.name) {
                                    // Проверяем контекст использования
                                    let parent = id.parent;
                                    while (parent) {
                                        if (parent.type === 'BinaryOperation' || 
                                            parent.type === 'Assignment' ||
                                            parent.type === 'UnaryOperation') {
                                            usedInArithmetic = true;
                                            break;
                                        }
                                        parent = parent.parent;
                                    }
                                }
                            }
                        });
                        
                        if (usedInArithmetic) {
                            findings.push(`OVERFLOW: Small integer type (${typeName}) used in arithmetic operations: variable "${n.name}"`);
                        }
                    }
                }
            }
        });
        
        return findings;
    }

    // ---------- 3. ACCESS CONTROL (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkAccessControl(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        const criticalOperations = [];
        
        // Собираем критические операции
        parser.visit(node.body, {
            // selfdestruct
            FunctionCall: function(n) {
                if (n.expression.name === 'selfdestruct') {
                    criticalOperations.push({
                        type: 'selfdestruct',
                        node: n,
                        text: sourceCode.substring(n.range[0], n.range[1])
                    });
                }
            },
            
            // delegatecall
            MemberAccess: function(n) {
                if (n.memberName === 'delegatecall') {
                    criticalOperations.push({
                        type: 'delegatecall',
                        node: n,
                        text: sourceCode.substring(n.range[0], n.parent.range[1])
                    });
                }
            },
            
            // mint/burn операции
            Identifier: function(n) {
                if (n.name && (n.name.toLowerCase().includes('mint') || 
                               n.name.toLowerCase().includes('burn'))) {
                    criticalOperations.push({
                        type: 'mint/burn',
                        node: n,
                        text: n.name
                    });
                }
            }
        });
        
        // Проверяем каждую критическую операцию
        for (const op of criticalOperations) {
            const hasControl = this.hasAccessControl(node, sourceCode);
            
            if (!hasControl) {
                findings.push(`ACCESS_CONTROL: Critical operation (${op.type}) found without proper access control at line ${this.getLineNumber(op.node.range[0], sourceCode)}`);
            }
        }
        
        return findings;
    }

    // ---------- 4. FRONT-RUNNING (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkFrontRunning(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        const funcName = func.name.toLowerCase();
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        // Определяем тип функции
        const isSwap = funcName.includes('swap') || funcName.includes('exchange') || funcName.includes('trade');
        const isLiquidity = funcName.includes('liquidity') || funcName.includes('add') || funcName.includes('remove');
        const isMint = funcName.includes('mint') || funcName.includes('claim') || funcName.includes('airdrop');
        
        let hasSlippage = false;
        let hasDeadline = false;
        let hasLimits = false;
        
        // Анализируем параметры функции
        if (node.parameters) {
            for (const param of node.parameters.parameters) {
                const paramName = param.name ? param.name.toLowerCase() : '';
                if (paramName.includes('min') || paramName.includes('max') || 
                    paramName.includes('slippage') || paramName.includes('amountout')) {
                    hasSlippage = true;
                }
                if (paramName.includes('deadline')) {
                    hasDeadline = true;
                }
                if (paramName.includes('limit') || paramName.includes('cap') || paramName.includes('max')) {
                    hasLimits = true;
                }
            }
        }
        
        // Анализируем тело функции
        parser.visit(node.body, {
            // Проверяем require/assert на slippage
            FunctionCall: function(n) {
                if (n.expression.name === 'require' || n.expression.name === 'assert') {
                    const checkText = sourceCode.substring(n.range[0], n.range[1]).toLowerCase();
                    if (checkText.includes('min') || checkText.includes('max') || 
                        checkText.includes('slippage') || checkText.includes('amountout')) {
                        hasSlippage = true;
                    }
                    if (checkText.includes('deadline') || checkText.includes('block.timestamp')) {
                        hasDeadline = true;
                    }
                    if (checkText.includes('limit') || checkText.includes('cap') || 
                        checkText.includes('max') || checkText.includes('only')) {
                        hasLimits = true;
                    }
                }
            },
            
            // Проверяем использование DEX функций
            MemberAccess: function(n) {
                const memberName = n.memberName.toLowerCase();
                if (memberName.includes('getamounts') || memberName.includes('getreserves')) {
                    // Если это DEX функция, проверяем наличие защиты
                    if (!hasSlippage) {
                        findings.push("FRONT_RUNNING: DEX operation detected without slippage protection");
                    }
                    if (!hasDeadline) {
                        findings.push("FRONT_RUNNING: DEX operation detected without deadline protection");
                    }
                }
            }
        });
        
        // Генерируем финальные findings
        if (isSwap && !hasSlippage) {
            findings.push("FRONT_RUNNING: Swap function lacks slippage protection (minAmount, maxAmount)");
        }
        if ((isSwap || isLiquidity) && !hasDeadline) {
            findings.push("FRONT_RUNNING: Function lacks deadline protection (block.timestamp check)");
        }
        if (isMint && !hasLimits) {
            findings.push("FRONT_RUNNING: Mint/claim function lacks anti-sniping protection (limits, caps)");
        }
        
        return findings;
    }

    // ---------- 5. TIMESTAMP DEPENDENCE (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkTimestampDependence(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        parser.visit(node.body, {
            MemberAccess: function(n) {
                if (n.expression.name === 'block' && n.memberName === 'timestamp') {
                    const context = this.getNodeContext(n, sourceCode, 150);
                    
                    // Пропускаем безопасные использования (deadline checks)
                    if (context.toLowerCase().includes('deadline')) {
                        return;
                    }
                    
                    // Проверяем использование для рандома
                    let parent = n;
                    while (parent) {
                        if (parent.type === 'BinaryOperation' && parent.operator === '%') {
                            findings.push(`TIMESTAMP_DEPENDENCE: Using block.timestamp for randomness at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                            return;
                        }
                        parent = parent.parent;
                    }
                    
                    // Проверяем маленькие временные окна
                    if (/(block\.timestamp\s*[+-]\s*[1-5])/i.test(context)) {
                        findings.push(`TIMESTAMP_DEPENDENCE: Small time window (< 5 seconds) at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                        return;
                    }
                    
                    // Проверяем использование в бизнес-логике
                    parent = n;
                    while (parent) {
                        if (parent.type === 'IfStatement' || 
                            (parent.type === 'FunctionCall' && 
                             (parent.expression.name === 'require' || 
                              parent.expression.name === 'assert'))) {
                            findings.push(`TIMESTAMP_DEPENDENCE: Business logic depends on timestamp at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                            return;
                        }
                        parent = parent.parent;
                    }
                }
            },
            
            Identifier: function(n) {
                if (n.name === 'now') {
                    findings.push(`TIMESTAMP_DEPENDENCE: Using deprecated 'now' keyword at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                }
            }
        });
        
        return findings;
    }

    // ---------- 6. DELEGATECALL (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkDelegatecallVulnerabilities(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        parser.visit(node.body, {
            MemberAccess: function(n) {
                if (n.memberName === 'delegatecall') {
                    const context = this.getNodeContext(n, sourceCode, 200);
                    
                    // ОПАСНО: delegatecall с user-controlled data
                    if (context.includes('msg.data')) {
                        findings.push(`DELEGATECALL: User-controlled delegatecall with msg.data at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                    }
                    
                    // Проверяем контроль доступа
                    const hasControl = this.hasAccessControl(node, sourceCode);
                    if (!hasControl) {
                        findings.push(`DELEGATECALL: Delegatecall without access control at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                    }
                }
            }
        });
        
        // Проверяем parity-style уязвимость (публичные функции с bytes параметром)
        if (node.visibility === 'public' || node.visibility === 'external') {
            if (node.parameters) {
                for (const param of node.parameters.parameters) {
                    if (param.typeName && param.typeName.name === 'bytes') {
                        findings.push(`DELEGATECALL: Public function with bytes parameter may allow arbitrary delegatecall (Parity-style vulnerability)`);
                        break;
                    }
                }
            }
        }
        
        return findings;
    }

    // ---------- 7. UNCHECKED CALLS (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkUncheckedCall(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        parser.visit(node.body, {
            FunctionCall: function(n) {
                if (n.expression.type === 'MemberAccess') {
                    const ma = n.expression;
                    const callText = sourceCode.substring(n.range[0], n.range[1]);
                    
                    // Проверяем ERC20 transfer/transferFrom
                    if (ma.memberName === 'transfer' || ma.memberName === 'transferFrom') {
                        let hasSuccessCheck = false;
                        
                        // Ищем проверку возвращаемого значения
                        let current = n;
                        while (current.parent) {
                            current = current.parent;
                            if (current.type === 'IfStatement') {
                                const ifText = sourceCode.substring(current.range[0], current.range[1]).toLowerCase();
                                if (ifText.includes('require') || ifText.includes('success') || ifText.includes('bool')) {
                                    hasSuccessCheck = true;
                                    break;
                                }
                            }
                        }
                        
                        if (!hasSuccessCheck) {
                            findings.push(`UNCHECKED_CALL: ERC20 ${ma.memberName}() without return value check at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                        }
                    }
                    
                    // Проверяем .send()
                    if (ma.memberName === 'send') {
                        let hasSuccessCheck = false;
                        let parent = n.parent;
                        
                        while (parent) {
                            if (parent.type === 'IfStatement' || 
                                (parent.type === 'FunctionCall' && 
                                 parent.expression.name === 'require')) {
                                hasSuccessCheck = true;
                                break;
                            }
                            parent = parent.parent;
                        }
                        
                        if (!hasSuccessCheck) {
                            findings.push(`UNCHECKED_CALL: .send() without success check at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                        }
                    }
                }
            }
        });
        
        return findings;
    }

    // ---------- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ----------
    static getLineNumber(pos, sourceCode) {
        // Простой, но эффективный способ получения номера строки
        const lines = sourceCode.substring(0, pos).split('\n');
        return lines.length;
    }

    static getNodeContext(node, sourceCode, chars = 100) {
        const start = Math.max(0, node.range[0] - chars);
        const end = Math.min(sourceCode.length, node.range[1] + chars);
        return sourceCode.substring(start, end);
    }
}

// ========== ГЛАВНАЯ ФУНКЦИЯ ==========
function analyzeSource(srcText) {
    try {
        const ast = parser.parse(srcText, { tolerant: true, range: true });
        const parserUtil = EnhancedParser;
        const checker = ProSecurityChecks;
        
        const pragma = parserUtil.findPragma(ast);
        const funcs = parserUtil.extractFunctions(ast, srcText);
        
        const report = [];
        
        for (const f of funcs) {
            const fFindings = [];
            
            // ВСЕ проверки как в твоём Python коде
            fFindings.push(...checker.checkReentrancy(f, srcText));
            fFindings.push(...checker.checkOverflow(f, pragma, srcText));
            fFindings.push(...checker.checkUncheckedCall(f, srcText));
            fFindings.push(...checker.checkAccessControl(f, srcText));
            fFindings.push(...checker.checkFrontRunning(f, srcText));
            fFindings.push(...checker.checkTimestampDependence(f, srcText));
            fFindings.push(...checker.checkDelegatecallVulnerabilities(f, srcText));
            
            if (fFindings.length > 0) {
                report.push({
                    function: f.name,
                    signature: f.signature,
                    issues: fFindings,
                    snippet: f.body.substring(0, 500) // Берем первые 500 символов тела
                });
            }
        }
        
        const globalMsgs = [];
        if (report.length === 0) {
            globalMsgs.push("No critical issues found. Рекомендуется дополнительная проверка с помощью Slither/Mythril.");
        }
        
        return {
            pragma: pragma,
            functions: report,
            global_msgs: globalMsgs
        };
        
    } catch (error) {
        return {
            error: `Parse error: ${error.message}`,
            functions: [],
            global_msgs: []
        };
    }
}

// ========== ИНТЕРФЕЙС ДЛЯ КОМАНДНОЙ СТРОКИ ==========
if (require.main === module) {
    // Если запускаем из командной строки
    const fs = require('fs');
    const path = require('path');
    
    if (process.argv.length > 2) {
        // Читаем код из файла
        const filePath = process.argv[2];
        try {
            const srcText = fs.readFileSync(filePath, 'utf8');
            const result = analyzeSource(srcText);
            console.log(JSON.stringify(result, null, 2));
        } catch (error) {
            console.error(JSON.stringify({
                error: `File read error: ${error.message}`,
                functions: [],
                global_msgs: []
            }, null, 2));
        }
    } else {
        // Тестовый режим (старый код)
        const testCode = `
        pragma solidity ^0.8.4;
        
        contract Test {
            mapping(address => uint) public balances;
            
            function withdraw() public {
                (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }
            
            function timestampVuln() public {
                // Уязвимость timestamp
                if (block.timestamp % 2 == 0) {
                    // do something
                }
            }
            
            function swap(uint amount) public {
                // Front-running уязвимость
                uint output = amount * 2;
                payable(msg.sender).transfer(output);
            }
        }
        `;
        
        console.log("=== SOLIDITY AST SCANNER PRO MAX ===");
        console.log("Тестовый режим...\n");
        
        const result = analyzeSource(testCode);
        
        if (result.error) {
            console.error("Ошибка:", result.error);
        } else {
            console.log("Pragma:", result.pragma || "Не найден");
            
            if (result.functions.length > 0) {
                console.log("\n=== НАЙДЕНЫ УЯЗВИМОСТИ ===");
                result.functions.forEach(func => {
                    console.log(`\nФункция: ${func.function}`);
                    console.log(`Сигнатура: ${func.signature}`);
                    console.log("Проблемы:");
                    func.issues.forEach((issue, i) => {
                        console.log(`  ${i + 1}. ${issue}`);
                    });
                });
            } else {
                console.log("\n✅ Уязвимостей не найдено!");
            }
        }
    }
}

// Экспорт для использования
module.exports = {
    analyzeSource,
    EnhancedParser,
    ProSecurityChecks
};
