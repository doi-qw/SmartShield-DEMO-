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
    if (start == null || end == null || start >= end) return '';
    const snippet = sourceCode.substring(start, end);
    if (snippet.length > maxLength) {
        return snippet.substring(0, maxLength) + '...';
    }
    return snippet;
}

// ========== ФИКС ДЛЯ AST (ДОБАВЛЕНИЕ parent) ==========
function attachParent(node, parent = null) {
    if (!node || typeof node !== 'object') return;
    
    node.parent = parent;
    
    for (const key in node) {
        if (key === 'parent') continue;
        
        const child = node[key];
        if (Array.isArray(child)) {
            for (const item of child) {
                if (item && typeof item === 'object') {
                    attachParent(item, node);
                }
            }
        } else if (child && typeof child === 'object') {
            attachParent(child, node);
        }
    }
}

// ========== УЛУЧШЕННЫЙ ПАРСЕР (ПРОДУКЦИОННЫЙ) ==========
class EnhancedParser {
    static findPragma(ast) {
        let pragma = null;
        if (!ast || !ast.children) return pragma;
        
        for (const child of ast.children) {
            if (child.type === 'PragmaDirective' && child.name === 'solidity') {
                pragma = child.value;
                break;
            }
        }
        return pragma;
    }

    static extractFunctions(ast, sourceCode) {
        const functions = [];
        
        if (!ast || !ast.children) return functions;
        
        const visitNode = (node) => {
            if (!node) return;
            
            if (node.type === 'FunctionDefinition') {
                // Извлекаем имя функции (конструктор может не иметь имени)
                const funcName = node.name || '<constructor>';
                
                // Извлекаем сигнатуру из исходного кода
                const signatureStart = node.range?.[0] || 0;
                let bodyStart = node.range?.[1] || 0;
                if (node.body && node.body.range) {
                    bodyStart = node.body.range[0];
                }
                const signature = sourceCode.substring(signatureStart, bodyStart).trim();
                
                // Извлекаем тело функции
                let body = '';
                if (node.body && node.body.range) {
                    body = getSourceSnippet(sourceCode, node.body.range[0], node.body.range[1]);
                }
                
                functions.push({
                    name: funcName,
                    signature: signature,
                    body: body,
                    astNode: node,
                    range: node.range || [0, 0],
                    bodyRange: node.body?.range || null
                });
            }
            
            // Рекурсивный обход детей
            for (const key in node) {
                if (key === 'parent' || key === 'range') continue;
                
                const child = node[key];
                if (Array.isArray(child)) {
                    for (const item of child) {
                        if (item && typeof item === 'object') {
                            visitNode(item);
                        }
                    }
                } else if (child && typeof child === 'object') {
                    visitNode(child);
                }
            }
        };
        
        visitNode(ast);
        return functions;
    }
}

// ========== ПРОДУКЦИОННЫЕ ПРОВЕРКИ PRO MAX ==========
class ProSecurityChecks {
    
    static isLibraryOrViewFunction(func) {
        const node = func.astNode;
        return node.stateMutability === 'view' || node.stateMutability === 'pure' || 
               node.visibility === 'pure' || node.visibility === 'view';
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
            this.visitAST(node.body, {
                FunctionCall: function(n) {
                    if (n.expression && n.expression.name === 'require' || n.expression?.name === 'assert') {
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

    // ---------- УНИВЕРСАЛЬНЫЙ VISIT С ПРОВЕРКАМИ ----------
    static visitAST(node, visitor) {
        if (!node || typeof node !== 'object') return;
        
        if (visitor[node.type]) {
            visitor[node.type](node);
        }
        
        for (const key in node) {
            if (key === 'parent' || key === 'range') continue;
            
            const child = node[key];
            if (Array.isArray(child)) {
                for (const item of child) {
                    if (item && typeof item === 'object') {
                        this.visitAST(item, visitor);
                    }
                }
            } else if (child && typeof child === 'object') {
                this.visitAST(child, visitor);
            }
        }
    }

    // ---------- 1. REENTRANCY (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkReentrancy(func, sourceCode) {
        const findings = [];
        const node = func.astNode;
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (this.hasReentrancyGuard(node)) return findings;
        if (!node.body) return findings;
        
        const externalCalls = [];
        const stateChanges = [];
        
        // Собираем ВСЕ внешние вызовы и изменения состояния
        this.visitAST(node.body, {
            // Внешние вызовы (call, transfer, send)
            FunctionCall: (n) => {
                if (n.expression && n.expression.type === 'MemberAccess') {
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
            Assignment: (n) => {
                if (!n.left || !n.left.range) return;
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
            UnaryOperation: (n) => {
                if ((n.isPrefix || n.isPostfix) && n.subExpression && n.subExpression.range) {
                    const opText = sourceCode.substring(n.range[0], n.range[1]).toLowerCase();
                    const subText = sourceCode.substring(n.subExpression.range[0], n.subExpression.range[1]).toLowerCase();
                    if (subText.includes('balance') || subText.includes('total')) {
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
                while (current && current.parent) {
                    current = current.parent;
                    if (current.type === 'IfStatement' || 
                        (current.type === 'FunctionCall' && 
                         current.expression && 
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
        if (node.body) {
            this.visitAST(node.body, {
                UncheckedStatement: (n) => {
                    // Проверяем, есть ли внутри арифметические операции
                    let hasArithmetic = false;
                    this.visitAST(n, {
                        BinaryOperation: (binOp) => {
                            if (['+', '-', '*', '/', '**'].includes(binOp.operator)) {
                                hasArithmetic = true;
                            }
                        },
                        Assignment: (assign) => {
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
        }
        
        // Для версий < 0.8.0 проверяем арифметику без SafeMath
        if (!builtinSafe) {
            let hasUnsafeArithmetic = false;
            let usesSafeMath = false;
            
            // Проверяем использование SafeMath
            this.visitAST(node, {
                UsingForDeclaration: (n) => {
                    if (n.libraryName && n.libraryName.toLowerCase().includes('safemath')) {
                        usesSafeMath = true;
                    }
                }
            });
            
            // Проверяем арифметические операции
            if (node.body) {
                this.visitAST(node.body, {
                    BinaryOperation: (n) => {
                        if (['+', '-', '*', '/', '**'].includes(n.operator)) {
                            hasUnsafeArithmetic = true;
                        }
                    },
                    Assignment: (n) => {
                        if (n.operator && ['+=', '-=', '*=', '/=', '**='].includes(n.operator)) {
                            hasUnsafeArithmetic = true;
                        }
                    }
                });
            }
            
            if (hasUnsafeArithmetic && !usesSafeMath) {
                findings.push("OVERFLOW: Arithmetic operations in Solidity < 0.8.0 without SafeMath library");
            }
        }
        
        // Проверяем маленькие типы (uint8, uint16, uint32)
        this.visitAST(node, {
            VariableDeclaration: (n) => {
                if (n.typeName && n.typeName.name) {
                    const typeName = n.typeName.name.toLowerCase();
                    if (typeName.includes('uint8') || typeName.includes('uint16') || typeName.includes('uint32')) {
                        // Проверяем, используется ли эта переменная в арифметике
                        let usedInArithmetic = false;
                        if (node.body) {
                            this.visitAST(node.body, {
                                Identifier: (id) => {
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
                        }
                        
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
        
        if (!node.body) return findings;
        
        // Собираем критические операции
        this.visitAST(node.body, {
            // selfdestruct
            FunctionCall: (n) => {
                if (n.expression && n.expression.name === 'selfdestruct') {
                    criticalOperations.push({
                        type: 'selfdestruct',
                        node: n,
                        text: sourceCode.substring(n.range[0], n.range[1])
                    });
                }
            },
            
            // delegatecall
            MemberAccess: (n) => {
                if (n.memberName === 'delegatecall') {
                    criticalOperations.push({
                        type: 'delegatecall',
                        node: n,
                        text: sourceCode.substring(n.range[0], n.parent.range[1])
                    });
                }
            },
            
            // mint/burn операции
            Identifier: (n) => {
                if (n.name && (n.name.toLowerCase().includes('mint') || 
                               n.name.toLowerCase().includes('burn'))) {
                    // Проверяем, что это вызов функции
                    let parent = n.parent;
                    while (parent && parent.type !== 'FunctionCall') {
                        parent = parent.parent;
                    }
                    if (parent && parent.type === 'FunctionCall') {
                        criticalOperations.push({
                            type: 'mint/burn',
                            node: n,
                            text: n.name
                        });
                    }
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
        if (node.body) {
            this.visitAST(node.body, {
                // Проверяем require/assert на slippage
                FunctionCall: (n) => {
                    if (n.expression && (n.expression.name === 'require' || n.expression.name === 'assert')) {
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
                MemberAccess: (n) => {
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
        }
        
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
        if (!node.body) return findings;
        
        this.visitAST(node.body, {
            MemberAccess: (n) => {
                if (n.expression && n.expression.name === 'block' && n.memberName === 'timestamp') {
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
                             parent.expression && 
                             (parent.expression.name === 'require' || 
                              parent.expression.name === 'assert'))) {
                            findings.push(`TIMESTAMP_DEPENDENCE: Business logic depends on timestamp at line ${this.getLineNumber(n.range[0], sourceCode)}`);
                            return;
                        }
                        parent = parent.parent;
                    }
                }
            },
            
            Identifier: (n) => {
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
        
        if (!node.body) return findings;
        
        this.visitAST(node.body, {
            MemberAccess: (n) => {
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
        if (!node.body) return findings;
        
        this.visitAST(node.body, {
            FunctionCall: (n) => {
                if (n.expression && n.expression.type === 'MemberAccess') {
                    const ma = n.expression;
                    const callText = sourceCode.substring(n.range[0], n.range[1]);
                    
                    // Проверяем ERC20 transfer/transferFrom
                    if (ma.memberName === 'transfer' || ma.memberName === 'transferFrom') {
                        let hasSuccessCheck = false;
                        
                        // Ищем проверку возвращаемого значения
                        let current = n;
                        while (current && current.parent) {
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
                                 parent.expression && 
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
        if (pos == null) return 'unknown';
        const lines = sourceCode.substring(0, pos).split('\n');
        return lines.length;
    }

    static getNodeContext(node, sourceCode, chars = 100) {
        if (!node.range) return '';
        const start = Math.max(0, node.range[0] - chars);
        const end = Math.min(sourceCode.length, node.range[1] + chars);
        return sourceCode.substring(start, end);
    }
}

// ========== ГЛАВНАЯ ФУНКЦИЯ ==========
function analyzeSource(srcText) {
    if (!srcText || typeof srcText !== 'string') {
        return {
            error: "Invalid source code: must be a non-empty string",
            functions: [],
            global_msgs: ["Ошибка: пустой исходный код"]
        };
    }
    
    try {
        const ast = parser.parse(srcText, { tolerant: true, range: true });
        
        // ФИКС №1: Добавляем parent ко всем узлам
        attachParent(ast);
        
        const parserUtil = EnhancedParser;
        const checker = ProSecurityChecks;
        
        const pragma = parserUtil.findPragma(ast);
        const funcs = parserUtil.extractFunctions(ast, srcText);
        
        const report = [];
        
        for (const f of funcs) {
            const fFindings = [];
            
            // Проверяем, что у функции есть тело
            if (!f.astNode.body) {
                // Если нет тела (интерфейс, абстрактная функция, конструктор без тела)
                if (f.name === '<constructor>') {
                    // Пустой конструктор - это нормально
                } else if (f.astNode.isAbstract || f.astNode.visibility === 'external') {
                    // Абстрактные или интерфейсные функции - нормально
                } else {
                    fFindings.push("FUNCTION_DECLARATION: Function declared but not implemented (interface or abstract contract)");
                }
                continue;
            }
            
            // ВСЕ проверки
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
                    snippet: f.body.substring(0, 500)
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
        // ФИКС №2: Не глушим ошибки, а возвращаем их в структурированном виде
        return {
            error: `Parse error: ${error.message}`,
            functions: [],
            global_msgs: ["❌ Ошибка парсинга Solidity кода. Проверьте синтаксис."],
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        };
    }
}

// ========== ИНТЕРФЕЙС ДЛЯ КОМАНДНОЙ СТРОКИ ==========
if (require.main === module) {
    const fs = require('fs');
    
    if (process.argv.length > 2) {
        const filePath = process.argv[2];
        try {
            const srcText = fs.readFileSync(filePath, 'utf8');
            const result = analyzeSource(srcText);
            console.log(JSON.stringify(result, null, 2));
        } catch (error) {
            console.error(JSON.stringify({
                error: `File read error: ${error.message}`,
                functions: [],
                global_msgs: ["❌ Ошибка чтения файла"]
            }, null, 2));
        }
    } else {
        // Тестовый режим
        const testCode = `
        pragma solidity ^0.8.4;
        
        contract Test {
            mapping(address => uint) public balances;
            
            function withdraw() public {
                (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }
            
            function timestampVuln() public {
                if (block.timestamp % 2 == 0) {
                    // do something
                }
            }
            
            function swap(uint amount) public {
                uint output = amount * 2;
                payable(msg.sender).transfer(output);
            }
            
            // Конструктор без тела
            constructor() {}
            
            // Fallback функция
            fallback() external {}
            
            // Receive функция
            receive() external payable {}
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
            
            if (result.global_msgs && result.global_msgs.length > 0) {
                console.log("\n=== СООБЩЕНИЯ ===");
                result.global_msgs.forEach(msg => console.log(`• ${msg}`));
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
