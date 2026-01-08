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
                
                // Извлекаем модификаторы
                const modifiers = node.modifiers ? node.modifiers.map(m => {
                    const modName = m.name || (m.namePath ? m.namePath.name : 'unknown');
                    return { name: modName };
                }) : [];
                
                // Извлекаем параметры
                let parameters = '';
                if (node.parameters) {
                    const params = node.parameters.parameters || [];
                    parameters = params.map(p => {
                        const paramName = p.name || '';
                        const paramType = p.typeName ? p.typeName.name || '' : '';
                        return `${paramType} ${paramName}`;
                    }).join(', ');
                }
                
                functions.push({
                    name: funcName,
                    signature: signature,
                    body: body,
                    parameters: parameters,
                    stateMutability: node.stateMutability || '',
                    visibility: node.visibility || 'public',
                    modifiers: modifiers,
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

// ========== ПРОДУКЦИОННЫЕ ПРОВЕРКИ PRO MAX (ИСПРАВЛЕННЫЕ) ==========
class ProSecurityChecks {
    
    static isLibraryOrViewFunction(func) {
        return func.stateMutability === 'view' || func.stateMutability === 'pure' || 
               func.visibility === 'pure' || func.visibility === 'view';
    }

    static hasReentrancyGuard(func) {
        if (!func.modifiers) return false;
        const guardModifiers = ['nonreentrant', 'reentrancyguard', 'locked', 'mutex', 'nolock'];
        return func.modifiers.some(mod => {
            const modName = mod.name ? mod.name.toLowerCase() : '';
            return guardModifiers.some(guard => modName.includes(guard));
        });
    }

    static hasAccessControl(func, sourceCode) {
        // Проверяем наличие модификаторов доступа
        if (func.modifiers) {
            const accessModifiers = ['onlyowner', 'onlyadmin', 'onlyrole', 'restricted', 'auth'];
            if (func.modifiers.some(mod => {
                const modName = mod.name ? mod.name.toLowerCase() : '';
                return accessModifiers.some(access => modName.includes(access));
            })) {
                return true;
            }
        }
        
        // Проверяем ручные проверки в теле функции
        if (func.body) {
            const bodyLower = func.body.toLowerCase();
            if (bodyLower.includes('require') || bodyLower.includes('assert')) {
                const lines = func.body.split('\n');
                for (const line of lines) {
                    const lowerLine = line.toLowerCase();
                    if ((lowerLine.includes('require') || lowerLine.includes('assert')) &&
                        lowerLine.includes('msg.sender') &&
                        (lowerLine.includes('owner') || lowerLine.includes('admin'))) {
                        return true;
                    }
                }
            }
        }
        
        return false;
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

    // ---------- 1. REENTRANCY (ИСПРАВЛЕННАЯ РЕАЛИЗАЦИЯ) ----------
    static checkReentrancy(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (this.hasReentrancyGuard(func)) return findings;
        if (!func.body) return findings;
        
        const body = func.body.toLowerCase();
        
        // 1. Проверяем наличие внешних вызовов
        const hasExternalCall = body.includes('.call{value:') || 
                               body.includes('.transfer(') || 
                               body.includes('.send(');
        
        if (!hasExternalCall) return findings;
        
        // 2. Разбиваем тело на строки для анализа CEI
        const lines = func.body.split('\n');
        let callLineIndex = -1;
        
        // Ищем строку с внешним вызовом
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].toLowerCase();
            if (line.includes('.call{value:') || 
                line.includes('.transfer(') || 
                line.includes('.send(')) {
                callLineIndex = i;
                break;
            }
        }
        
        if (callLineIndex === -1) return findings;
        
        // 3. Ищем изменения состояния ПОСЛЕ вызова
        for (let i = callLineIndex + 1; i < lines.length; i++) {
            const line = lines[i].toLowerCase();
            
            // Ищем изменения балансов, totals, supply
            if (line.includes('balance[') || 
                line.includes('balances[') ||
                (line.includes('balance') && line.includes('=')) ||
                line.includes('total=') ||
                line.includes('supply=') ||
                (line.includes('total') && line.includes('=')) ||
                (line.includes('supply') && line.includes('='))) {
                
                // Проверяем, есть ли проверка между вызовом и изменением состояния
                let hasCheckBetween = false;
                for (let j = callLineIndex + 1; j < i; j++) {
                    if (lines[j].includes('require(') || 
                        lines[j].includes('assert(') ||
                        lines[j].includes('if (')) {
                        hasCheckBetween = true;
                        break;
                    }
                }
                
                if (!hasCheckBetween) {
                    findings.push("REENTRANCY: External call before state update - violates CEI pattern");
                    break;
                }
            }
        }
        
        // 4. Проверяем unchecked calls
        if (body.includes('.call{value:') && !body.includes('success')) {
            findings.push("UNCHECKED_CALL: Value transfer without success check");
        }
        
        // 5. Дополнительный AST анализ если доступен
        if (func.astNode && func.astNode.body) {
            const externalCalls = [];
            const stateChanges = [];
            
            this.visitAST(func.astNode.body, {
                FunctionCall: (node) => {
                    if (node.expression && node.expression.type === 'MemberAccess') {
                        const ma = node.expression;
                        if (ma.memberName === 'call' || ma.memberName === 'transfer' || ma.memberName === 'send') {
                            externalCalls.push({
                                node: node,
                                pos: node.range?.[0] || 0
                            });
                        }
                    }
                },
                
                Assignment: (node) => {
                    // Проверяем IndexAccess (mapping[key] = value)
                    if (node.left && node.left.type === 'IndexAccess') {
                        if (node.left.base && node.left.base.name) {
                            const baseName = node.left.base.name.toLowerCase();
                            if (baseName.includes('balance') || 
                                baseName.includes('total') || 
                                baseName.includes('supply')) {
                                stateChanges.push({
                                    node: node,
                                    pos: node.range?.[0] || 0
                                });
                            }
                        }
                    }
                    // Проверяем простые присваивания
                    else if (node.left && node.left.name) {
                        const leftName = node.left.name.toLowerCase();
                        if (leftName.includes('balance') || 
                            leftName.includes('total') || 
                            leftName.includes('supply')) {
                            stateChanges.push({
                                node: node,
                                pos: node.range?.[0] || 0
                            });
                        }
                    }
                }
            });
            
            // Проверяем CEI violation в AST
            for (const call of externalCalls) {
                for (const state of stateChanges) {
                    if (call.pos < state.pos) {
                        const betweenCode = sourceCode.substring(call.pos, state.pos);
                        if (!betweenCode.includes('require(') && 
                            !betweenCode.includes('assert(') && 
                            !betweenCode.includes('if (')) {
                            
                            if (!findings.includes("REENTRANCY: External call before state update - violates CEI pattern")) {
                                findings.push("REENTRANCY: External call before state update - violates CEI pattern");
                            }
                        }
                    }
                }
            }
        }
        
        return findings;
    }

    // ---------- 2. OVERFLOW/UNDERFLOW (ИСПРАВЛЕННАЯ РЕАЛИЗАЦИЯ) ----------
    static checkOverflow(func, pragma, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        const version = parseVersionFromPragma(pragma);
        const builtinSafe = versionGe(version, [0, 8, 0]);
        
        // Проверяем unchecked блоки
        if (func.body && func.body.includes('unchecked')) {
            findings.push("OVERFLOW: 'unchecked' block found");
        }
        
        // Для версий < 0.8.0 проверяем арифметику без SafeMath
        if (!builtinSafe) {
            const hasArithmetic = func.body && /[\+\-\*\/]\=|\+\+|\-\-|\+|\-|\*|\//.test(func.body);
            const usesSafeMath = sourceCode.toLowerCase().includes('safemath');
            
            if (hasArithmetic && !usesSafeMath) {
                findings.push("OVERFLOW: Arithmetic operations in Solidity < 0.8.0 without SafeMath library");
            }
        }
        
        // Проверяем маленькие типы
        if (func.signature || func.parameters) {
            const searchText = (func.signature + ' ' + func.parameters).toLowerCase();
            const smallTypes = ['uint8', 'uint16', 'uint32'];
            
            for (const type of smallTypes) {
                if (searchText.includes(type)) {
                    // Проверяем использование в арифметике
                    if (func.body && /[\+\-\*\/]/.test(func.body)) {
                        findings.push(`OVERFLOW: Small integer type (${type}) used in arithmetic operations`);
                        break;
                    }
                }
            }
        }
        
        // AST анализ для unchecked арифметики
        if (func.astNode && func.astNode.body) {
            let hasUnsafeArithmetic = false;
            
            this.visitAST(func.astNode.body, {
                UncheckedStatement: () => {
                    // Нашли unchecked блок
                    if (!findings.some(f => f.includes("'unchecked'"))) {
                        findings.push("OVERFLOW: 'unchecked' block found");
                    }
                },
                
                BinaryOperation: (node) => {
                    if (['+', '-', '*', '/', '**', '%'].includes(node.operator)) {
                        hasUnsafeArithmetic = true;
                    }
                },
                
                Assignment: (node) => {
                    if (node.operator && ['+=', '-=', '*=', '/=', '**=', '%='].includes(node.operator)) {
                        hasUnsafeArithmetic = true;
                    }
                }
            });
            
            if (hasUnsafeArithmetic && !builtinSafe && !sourceCode.toLowerCase().includes('safemath')) {
                if (!findings.some(f => f.includes("Arithmetic operations"))) {
                    findings.push("OVERFLOW: Unsafe arithmetic operations detected");
                }
            }
        }
        
        return findings;
    }

    // ---------- 3. ACCESS CONTROL (ИСПРАВЛЕННАЯ РЕАЛИЗАЦИЯ) ----------
    static checkAccessControl(func, sourceCode) {
        const findings = [];
        
        const criticalOperations = [];
        const funcName = func.name.toLowerCase();
        
        // Критические функции по имени
        if (funcName.includes('mint') || funcName.includes('burn') || 
            funcName.includes('admin') || funcName.includes('owner') ||
            funcName === 'kill' || funcName.includes('destroy')) {
            criticalOperations.push({
                type: 'privileged function',
                name: func.name
            });
        }
        
        // Проверяем тело функции на критические операции
        if (func.body) {
            const bodyLower = func.body.toLowerCase();
            
            if (bodyLower.includes('selfdestruct(')) {
                criticalOperations.push({
                    type: 'selfdestruct',
                    name: func.name
                });
            }
            
            if (bodyLower.includes('delegatecall')) {
                criticalOperations.push({
                    type: 'delegatecall',
                    name: func.name
                });
            }
        }
        
        // AST анализ для selfdestruct
        if (func.astNode && func.astNode.body) {
            this.visitAST(func.astNode.body, {
                FunctionCall: (node) => {
                    if (node.expression && node.expression.name === 'selfdestruct') {
                        criticalOperations.push({
                            type: 'selfdestruct',
                            name: func.name
                        });
                    }
                }
            });
        }
        
        // Проверяем каждую критическую операцию
        for (const op of criticalOperations) {
            const hasControl = this.hasAccessControl(func, sourceCode);
            
            if (!hasControl) {
                findings.push(`ACCESS_CONTROL: Critical operation (${op.type}) found without proper access control`);
            }
        }
        
        return findings;
    }

    // ---------- 4. FRONT-RUNNING (ИСПРАВЛЕННАЯ РЕАЛИЗАЦИЯ) ----------
    static checkFrontRunning(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        const lowerName = func.name.toLowerCase();
        const isSwap = lowerName.includes('swap') || lowerName.includes('exchange') || lowerName.includes('trade');
        const isLiquidity = lowerName.includes('liquidity') || lowerName.includes('add') || lowerName.includes('remove');
        const isMint = lowerName.includes('mint') || lowerName.includes('claim') || lowerName.includes('airdrop');
        
        if (!isSwap && !isLiquidity && !isMint) return findings;
        
        let hasSlippage = false;
        let hasDeadline = false;
        let hasLimits = false;
        
        // Проверяем параметры
        if (func.parameters) {
            const lowerParams = func.parameters.toLowerCase();
            if (lowerParams.includes('min') || lowerParams.includes('max') || 
                lowerParams.includes('slippage') || lowerParams.includes('amountout')) {
                hasSlippage = true;
            }
            if (lowerParams.includes('deadline')) {
                hasDeadline = true;
            }
            if (lowerParams.includes('limit') || lowerParams.includes('cap') || lowerParams.includes('max')) {
                hasLimits = true;
            }
        }
        
        // Проверяем тело
        if (func.body) {
            const lowerBody = func.body.toLowerCase();
            
            // Проверяем на slippage protection
            if (lowerBody.includes('min') || lowerBody.includes('max') || 
                lowerBody.includes('slippage') || lowerBody.includes('amountout')) {
                hasSlippage = true;
            }
            
            // Проверяем на deadline protection
            if (lowerBody.includes('deadline') || 
                (lowerBody.includes('block.timestamp') && 
                 (lowerBody.includes('require') || lowerBody.includes('assert') || lowerBody.includes('if')))) {
                hasDeadline = true;
            }
            
            // Проверяем на limits/caps
            if (lowerBody.includes('limit') || lowerBody.includes('cap') || 
                lowerBody.includes('max') || lowerBody.includes('only')) {
                hasLimits = true;
            }
        }
        
        // Проверяем функцию swap
        if (isSwap && !hasSlippage) {
            findings.push("FRONT_RUNNING: Swap function lacks slippage protection (minAmount, maxAmount)");
        }
        
        // Проверяем функции swap и liquidity
        if ((isSwap || isLiquidity) && !hasDeadline) {
            findings.push("FRONT_RUNNING: Function lacks deadline protection (block.timestamp check)");
        }
        
        // Проверяем функции mint
        if (isMint && !hasLimits) {
            findings.push("FRONT_RUNNING: Mint/claim function lacks anti-sniping protection (limits, caps)");
        }
        
        return findings;
    }

    // ---------- 5. TIMESTAMP DEPENDENCE (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkTimestampDependence(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (!func.body) return findings;
        
        const bodyLower = func.body.toLowerCase();
        
        // Проверяем использование block.timestamp для рандома
        if (bodyLower.includes('block.timestamp %') || 
            bodyLower.includes('block.timestamp &') ||
            bodyLower.includes('block.timestamp <<') ||
            bodyLower.includes('block.timestamp >>')) {
            findings.push("TIMESTAMP_DEPENDENCE: Using block.timestamp for randomness");
        }
        
        // Проверяем маленькие временные окна
        if (/block\.timestamp\s*[\+\-]\s*[1-5]/.test(bodyLower)) {
            findings.push("TIMESTAMP_DEPENDENCE: Small time window (< 5 seconds)");
        }
        
        // Проверяем использование в бизнес-логике (кроме deadline проверок)
        if (bodyLower.includes('block.timestamp') && 
            !bodyLower.includes('deadline') &&
            (bodyLower.includes('if') || bodyLower.includes('require') || bodyLower.includes('assert'))) {
            
            // Исключаем случаи с deadline
            const lines = func.body.split('\n');
            let isBusinessLogic = false;
            
            for (const line of lines) {
                const lowerLine = line.toLowerCase();
                if (lowerLine.includes('block.timestamp') && 
                    !lowerLine.includes('deadline') &&
                    (lowerLine.includes('if') || lowerLine.includes('require') || lowerLine.includes('assert'))) {
                    isBusinessLogic = true;
                    break;
                }
            }
            
            if (isBusinessLogic && !findings.some(f => f.includes("timestamp"))) {
                findings.push("TIMESTAMP_DEPENDENCE: Business logic depends on timestamp");
            }
        }
        
        // Проверяем устаревший 'now'
        if (bodyLower.includes(' now ') || bodyLower.includes('(now)')) {
            findings.push("TIMESTAMP_DEPENDENCE: Using deprecated 'now' keyword");
        }
        
        return findings;
    }

    // ---------- 6. DELEGATECALL (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkDelegatecallVulnerabilities(func, sourceCode) {
        const findings = [];
        
        // Проверяем parity-style уязвимость
        if ((func.visibility === 'public' || func.visibility === 'external') && 
            func.parameters && func.parameters.includes('bytes')) {
            findings.push("DELEGATECALL: Public function with bytes parameter may allow arbitrary delegatecall (Parity-style vulnerability)");
        }
        
        if (!func.body) return findings;
        
        const bodyLower = func.body.toLowerCase();
        
        // Проверяем наличие delegatecall
        if (bodyLower.includes('delegatecall')) {
            findings.push("DELEGATECALL: Delegatecall found");
            
            // Проверяем user-controlled data
            if (bodyLower.includes('msg.data')) {
                findings.push("DELEGATECALL: User-controlled delegatecall with msg.data");
            }
        }
        
        // AST анализ для delegatecall
        if (func.astNode && func.astNode.body) {
            this.visitAST(func.astNode.body, {
                MemberAccess: (node) => {
                    if (node.memberName === 'delegatecall') {
                        if (!findings.some(f => f.includes("Delegatecall found"))) {
                            findings.push("DELEGATECALL: Delegatecall found");
                        }
                        
                        // Проверяем контекст вызова
                        let parent = node.parent;
                        while (parent) {
                            if (parent.type === 'FunctionCall' && parent.arguments) {
                                const callText = sourceCode.substring(
                                    parent.range[0], 
                                    parent.range[1]
                                ).toLowerCase();
                                
                                if (callText.includes('msg.data')) {
                                    findings.push("DELEGATECALL: User-controlled delegatecall with msg.data");
                                }
                                break;
                            }
                            parent = parent.parent;
                        }
                    }
                }
            });
        }
        
        return findings;
    }

    // ---------- 7. UNCHECKED CALLS (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkUncheckedCall(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (!func.body) return findings;
        
        const body = func.body;
        const bodyLower = body.toLowerCase();
        
        // Проверяем ERC20 transfer/transferFrom
        if (bodyLower.includes('.transfer(') || bodyLower.includes('.transferfrom(')) {
            // Ищем проверку возвращаемого значения
            let hasCheck = false;
            
            // Простая проверка по наличию require/if вокруг
            const lines = body.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].toLowerCase();
                if (line.includes('.transfer(') || line.includes('.transferfrom(')) {
                    // Проверяем следующие строки на наличие проверок
                    for (let j = Math.max(0, i - 3); j < Math.min(lines.length, i + 3); j++) {
                        const checkLine = lines[j].toLowerCase();
                        if (checkLine.includes('require') || 
                            checkLine.includes('assert') || 
                            (checkLine.includes('if') && checkLine.includes('success'))) {
                            hasCheck = true;
                            break;
                        }
                    }
                    if (!hasCheck) {
                        findings.push("UNCHECKED_CALL: ERC20 transfer/transferFrom without return value check");
                        break;
                    }
                }
            }
        }
        
        // Проверяем .send()
        if (bodyLower.includes('.send(') && !bodyLower.includes('if') && 
            !bodyLower.includes('require') && !bodyLower.includes('assert')) {
            findings.push("UNCHECKED_CALL: .send() without success check");
        }
        
        // Проверяем .call() с value
        if (bodyLower.includes('.call{value:') && !bodyLower.includes('success')) {
            findings.push("UNCHECKED_CALL: Value transfer without success check");
        }
        
        return findings;
    }

    // ---------- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ----------
    static getLineNumber(pos, sourceCode) {
        if (pos == null) return 'unknown';
        const lines = sourceCode.substring(0, pos).split('\n');
        return lines.length;
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
            if (!f.body || f.body.trim().length === 0) {
                // Если нет тела (интерфейс, абстрактная функция, конструктор без тела)
                if (f.name === '<constructor>' || f.name === 'fallback' || f.name === 'receive') {
                    continue;
                } else if (f.visibility === 'external' || f.stateMutability === 'virtual') {
                    // Абстрактные или интерфейсные функции - пропускаем
                    continue;
                }
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
                    signature: f.signature.substring(0, 200),
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

// Экспорт для использования
module.exports = {
    analyzeSource,
    EnhancedParser,
    ProSecurityChecks
};
