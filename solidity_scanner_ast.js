const solc = require('solc');

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

// ========== ПАРСЕР НА ОСНОВЕ SOLC (ПОЛНЫЙ AST) ==========
class SolidityParser {
    static parse(sourceCode) {
        try {
            const input = {
                language: 'Solidity',
                sources: {
                    'contract.sol': {
                        content: sourceCode
                    }
                },
                settings: {
                    outputSelection: {
                        '*': {
                            '*': ['ast']
                        }
                    }
                }
            };
            
            const output = JSON.parse(solc.compile(JSON.stringify(input)));
            
            if (output.errors && output.errors.length > 0) {
                const parseErrors = output.errors.filter(e => e.severity === 'error');
                if (parseErrors.length > 0) {
                    throw new Error(parseErrors[0].message);
                }
            }
            
            const contractName = Object.keys(output.sources['contract.sol'].ast.nodes[0].nodes || {})[0] || 'Contract';
            const ast = output.sources['contract.sol'].ast;
            
            return {
                ast: ast,
                pragma: this.extractPragma(ast),
                functions: this.extractFunctions(ast, sourceCode)
            };
            
        } catch (error) {
            // Fallback на простой парсинг
            console.warn("AST parsing failed, using fallback:", error.message);
            return this.simpleParse(sourceCode);
        }
    }
    
    static extractPragma(ast) {
        if (!ast || !ast.nodes) return null;
        
        for (const node of ast.nodes) {
            if (node.nodeType === 'PragmaDirective' && node.name === 'solidity') {
                return node.value;
            }
        }
        return null;
    }
    
    static extractFunctions(ast, sourceCode) {
        const functions = [];
        
        if (!ast || !ast.nodes) return functions;
        
        const traverse = (nodes) => {
            if (!nodes) return;
            
            for (const node of nodes) {
                if (node.nodeType === 'FunctionDefinition') {
                    const funcName = node.name || '<constructor>';
                    const start = node.src.split(':')[0];
                    const length = node.src.split(':')[1];
                    
                    // Извлекаем сигнатуру
                    let signature = '';
                    let body = '';
                    
                    if (node.body) {
                        const bodyStart = parseInt(node.body.src.split(':')[0]);
                        const bodyLength = parseInt(node.body.src.split(':')[1]);
                        body = sourceCode.substring(bodyStart, bodyStart + bodyLength);
                        
                        // Сигнатура = всё до тела
                        signature = sourceCode.substring(parseInt(start), bodyStart).trim();
                    } else {
                        signature = sourceCode.substring(parseInt(start), parseInt(start) + parseInt(length)).trim();
                    }
                    
                    // Извлекаем параметры
                    const parameters = node.parameters ? 
                        this.extractParameters(node.parameters, sourceCode) : '';
                    
                    // Извлекаем модификаторы
                    const modifiers = node.modifiers ? 
                        node.modifiers.map(m => ({ name: m.modifierName.name || m.modifierName })) : [];
                    
                    functions.push({
                        name: funcName,
                        signature: signature,
                        body: body,
                        parameters: parameters,
                        stateMutability: node.stateMutability || '',
                        visibility: node.visibility || 'public',
                        modifiers: modifiers,
                        astNode: node,
                        src: node.src
                    });
                }
                
                // Рекурсивный обход
                if (node.nodes) traverse(node.nodes);
                if (node.body && node.body.nodes) traverse([node.body]);
                if (node.parameters && node.parameters.parameters) {
                    for (const param of node.parameters.parameters) {
                        if (param.nodes) traverse(param.nodes);
                    }
                }
            }
        };
        
        traverse(ast.nodes);
        return functions;
    }
    
    static extractParameters(paramList, sourceCode) {
        if (!paramList || !paramList.parameters) return '';
        
        const start = parseInt(paramList.src.split(':')[0]);
        const length = parseInt(paramList.src.split(':')[1]);
        return sourceCode.substring(start, start + length);
    }
    
    static simpleParse(sourceCode) {
        // ... (полный код простого парсера как в предыдущем сообщении, ~100 строк)
        // Возвращаем { pragma, functions } структуру
        const lines = sourceCode.split('\n');
        let pragma = null;
        const functions = [];
        
        // Извлекаем pragma
        for (const line of lines) {
            if (line.includes('pragma solidity')) {
                const match = line.match(/pragma solidity\s*(.*?);/);
                if (match) pragma = match[1];
                break;
            }
        }
        
        // Продвинутый парсинг функций с учетом скобок
        let inFunction = false;
        let currentFunc = null;
        let braceCount = 0;
        let funcStartLine = 0;
        let funcLines = [];
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            const fullLine = lines[i];
            
            if (!inFunction) {
                // Ищем начало функции
                if ((line.startsWith('function ') || 
                     line.startsWith('constructor') ||
                     line.startsWith('receive') ||
                     line.startsWith('fallback')) && 
                    (line.includes('{') || line.includes(';') || 
                     (i + 1 < lines.length && lines[i + 1].trim().startsWith('{')))) {
                    
                    currentFunc = {
                        name: this.extractFunctionName(line),
                        signature: line,
                        body: '',
                        stateMutability: this.extractStateMutability(line),
                        visibility: this.extractVisibility(line),
                        modifiers: this.extractModifiers(line),
                        parameters: this.extractParametersSimple(line)
                    };
                    
                    inFunction = true;
                    funcStartLine = i;
                    funcLines = [fullLine];
                    braceCount = this.countBraces(line);
                    
                    // Если функция начинается сразу с {
                    if (line.includes('{')) {
                        if (braceCount === 0) {
                            // Завершаем функцию
                            functions.push(currentFunc);
                            inFunction = false;
                            currentFunc = null;
                        }
                    }
                }
            } else if (currentFunc) {
                funcLines.push(fullLine);
                braceCount += this.countBraces(fullLine);
                
                if (braceCount === 0) {
                    // Завершаем функцию
                    const fullFunction = funcLines.join('\n');
                    const bodyStart = fullFunction.indexOf('{');
                    const bodyEnd = fullFunction.lastIndexOf('}');
                    
                    if (bodyStart !== -1 && bodyEnd !== -1) {
                        currentFunc.body = fullFunction.substring(bodyStart + 1, bodyEnd).trim();
                        currentFunc.signature = fullFunction.substring(0, bodyStart).trim();
                    }
                    
                    functions.push(currentFunc);
                    inFunction = false;
                    currentFunc = null;
                }
            }
        }
        
        return { ast: null, pragma: pragma, functions: functions };
    }
    
    static extractFunctionName(line) {
        if (line.includes('constructor')) return '<constructor>';
        if (line.includes('fallback')) return 'fallback';
        if (line.includes('receive')) return 'receive';
        
        const match = line.match(/function\s+(\w+)\s*\(/);
        return match ? match[1] : 'unknown';
    }
    
    static extractStateMutability(line) {
        if (line.includes('view')) return 'view';
        if (line.includes('pure')) return 'pure';
        if (line.includes('payable')) return 'payable';
        return '';
    }
    
    static extractVisibility(line) {
        if (line.includes('public')) return 'public';
        if (line.includes('private')) return 'private';
        if (line.includes('internal')) return 'internal';
        if (line.includes('external')) return 'external';
        return 'public';
    }
    
    static extractModifiers(line) {
        const modifiers = [];
        const parts = line.split('function')[1] || line;
        const modifierRegex = /(\w+)(?=\s*(?:\(|\{|;|\)|\n))/g;
        
        let match;
        while ((match = modifierRegex.exec(parts)) !== null) {
            const mod = match[1];
            if (!['public', 'private', 'internal', 'external', 
                  'view', 'pure', 'payable', 'returns', 'function'].includes(mod.toLowerCase())) {
                modifiers.push({ name: mod });
            }
        }
        
        return modifiers;
    }
    
    static extractParametersSimple(line) {
        const match = line.match(/\((.*?)\)/);
        return match ? match[1] : '';
    }
    
    static countBraces(line) {
        let count = 0;
        for (const char of line) {
            if (char === '{') count++;
            if (char === '}') count--;
        }
        return count;
    }
}

// ========== AST TRAVERSAL УТИЛИТЫ ==========
class ASTTraverser {
    static traverse(node, visitor, parent = null) {
        if (!node || typeof node !== 'object') return;
        
        // Добавляем parent ссылку
        node.parent = parent;
        
        // Вызываем visitor для текущего узла
        if (visitor[node.nodeType]) {
            visitor[node.nodeType](node);
        }
        
        // Рекурсивный обход всех дочерних узлов
        for (const key in node) {
            if (key === 'parent' || key === 'src') continue;
            
            const child = node[key];
            if (Array.isArray(child)) {
                for (const item of child) {
                    if (item && typeof item === 'object') {
                        this.traverse(item, visitor, node);
                    }
                }
            } else if (child && typeof child === 'object') {
                this.traverse(child, visitor, node);
            }
        }
    }
    
    static findNodes(node, predicate) {
        const results = [];
        this.traverse(node, {
            '*': (n) => {
                if (predicate(n)) {
                    results.push(n);
                }
            }
        });
        return results;
    }
}

// ========== ПРОДУКЦИОННЫЕ ПРОВЕРКИ PRO MAX (ПОЛНАЯ ВЕРСИЯ) ==========
class ProSecurityChecks {
    
    static isLibraryOrViewFunction(func) {
        return func.stateMutability === 'view' || func.stateMutability === 'pure' || 
               func.visibility === 'pure' || func.visibility === 'view';
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
        
        // Проверяем ручные проверки в теле
        if (node.body && sourceCode) {
            const bodyLower = node.body.toLowerCase();
            if (bodyLower.includes('require') || bodyLower.includes('assert')) {
                // Ищем проверки с msg.sender
                const lines = node.body.split('\n');
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

    // ---------- 1. REENTRANCY (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkReentrancy(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (this.hasReentrancyGuard(func)) return findings;
        if (!func.body || !func.astNode) return findings;
        
        const externalCalls = [];
        const stateChanges = [];
        
        // Анализируем AST
        ASTTraverser.traverse(func.astNode.body, {
            FunctionCall: (node) => {
                if (node.expression && node.expression.nodeType === 'MemberAccess') {
                    const ma = node.expression;
                    const callSrc = this.getSourceFromNode(node, sourceCode);
                    
                    if (ma.memberName === 'call' || ma.memberName === 'transfer' || ma.memberName === 'send') {
                        externalCalls.push({
                            node: node,
                            text: callSrc,
                            pos: parseInt(node.src.split(':')[0]),
                            isValueTransfer: callSrc.includes('value:') || 
                                           ma.memberName === 'transfer' || 
                                           ma.memberName === 'send'
                        });
                    }
                }
            },
            
            Assignment: (node) => {
                const assignSrc = this.getSourceFromNode(node, sourceCode);
                const leftSrc = node.left ? this.getSourceFromNode(node.left, sourceCode) : '';
                
                if (leftSrc.toLowerCase().includes('balance') || 
                    leftSrc.toLowerCase().includes('total') || 
                    leftSrc.toLowerCase().includes('supply')) {
                    
                    stateChanges.push({
                        node: node,
                        text: assignSrc,
                        pos: parseInt(node.src.split(':')[0])
                    });
                }
            }
        });
        
        // Проверяем CEI violation
        for (const call of externalCalls) {
            for (const state of stateChanges) {
                if (call.pos < state.pos) {
                    const betweenCode = sourceCode.substring(call.pos, state.pos);
                    if (!betweenCode.includes('require(') && 
                        !betweenCode.includes('assert(') && 
                        !betweenCode.includes('if (') &&
                        !betweenCode.includes('revert')) {
                        
                        findings.push(`REENTRANCY: External call before state update - violates CEI pattern`);
                    }
                }
            }
            
            // Проверяем unchecked calls
            if (call.isValueTransfer) {
                let hasSuccessCheck = false;
                let current = call.node;
                
                while (current && current.parent) {
                    current = current.parent;
                    if (current.nodeType === 'IfStatement' || 
                        (current.nodeType === 'FunctionCall' && 
                         current.expression && 
                         (current.expression.name === 'require' || 
                          current.expression.name === 'assert'))) {
                        
                        const checkText = this.getSourceFromNode(current, sourceCode).toLowerCase();
                        if (checkText.includes('success') || checkText.includes('ok')) {
                            hasSuccessCheck = true;
                            break;
                        }
                    }
                }
                
                if (!hasSuccessCheck) {
                    findings.push(`UNCHECKED_CALL: Value transfer without success check`);
                }
            }
        }
        
        // Regex fallback если AST анализ не сработал
        if (findings.length === 0 && func.body) {
            if (func.body.includes('.call{value:') && func.body.includes('balance[') && 
                func.body.indexOf('.call{value:') < func.body.indexOf('balance[')) {
                findings.push("REENTRANCY: Potential CEI violation found (call before balance update)");
            }
        }
        
        return findings;
    }

    // ---------- 2. OVERFLOW/UNDERFLOW (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkOverflow(func, pragma, sourceCode) {
        const findings = [];
        
        const version = parseVersionFromPragma(pragma);
        const builtinSafe = versionGe(version, [0, 8, 0]);
        
        // Ищем unchecked блоки в AST
        if (func.astNode && func.astNode.body) {
            ASTTraverser.traverse(func.astNode.body, {
                UncheckedStatement: (node) => {
                    findings.push("OVERFLOW: 'unchecked' block found");
                }
            });
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
        if (func.signature) {
            const smallTypes = ['uint8', 'uint16', 'uint32'];
            for (const type of smallTypes) {
                if (func.signature.includes(type) && func.body && /[\+\-\*\/]/.test(func.body)) {
                    findings.push(`OVERFLOW: Small integer type (${type}) used in arithmetic`);
                    break;
                }
            }
        }
        
        // Проверяем unchecked арифметику в AST
        if (func.astNode) {
            let hasUnsafeArithmetic = false;
            ASTTraverser.traverse(func.astNode, {
                BinaryOperation: (node) => {
                    if (['+', '-', '*', '/', '**', '%'].includes(node.operator)) {
                        // Проверяем, есть ли unchecked блок выше
                        let parent = node.parent;
                        let inUnchecked = false;
                        while (parent) {
                            if (parent.nodeType === 'UncheckedStatement') {
                                inUnchecked = true;
                                break;
                            }
                            parent = parent.parent;
                        }
                        
                        if (!inUnchecked && !builtinSafe) {
                            hasUnsafeArithmetic = true;
                        }
                    }
                }
            });
            
            if (hasUnsafeArithmetic && !sourceCode.toLowerCase().includes('safemath')) {
                findings.push("OVERFLOW: Unsafe arithmetic operations detected");
            }
        }
        
        return findings;
    }

    // ---------- 3. ACCESS CONTROL (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkAccessControl(func, sourceCode) {
        const findings = [];
        
        const criticalOperations = [];
        
        // Анализируем AST для критических операций
        if (func.astNode && func.astNode.body) {
            ASTTraverser.traverse(func.astNode.body, {
                FunctionCall: (node) => {
                    if (node.expression && node.expression.name === 'selfdestruct') {
                        criticalOperations.push({
                            type: 'selfdestruct',
                            node: node
                        });
                    }
                },
                
                MemberAccess: (node) => {
                    if (node.memberName === 'delegatecall') {
                        criticalOperations.push({
                            type: 'delegatecall',
                            node: node
                        });
                    }
                }
            });
        }
        
        // Также проверяем по имени функции
        const lowerName = func.name.toLowerCase();
        if (lowerName.includes('mint') || lowerName.includes('burn') || 
            lowerName.includes('admin') || lowerName.includes('owner')) {
            criticalOperations.push({
                type: 'privileged function',
                node: func.astNode
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

    // ---------- 4. FRONT-RUNNING (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkFrontRunning(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        
        const lowerName = func.name.toLowerCase();
        const isSwap = lowerName.includes('swap') || lowerName.includes('exchange');
        const isLiquidity = lowerName.includes('liquidity') || lowerName.includes('add') || lowerName.includes('remove');
        const isMint = lowerName.includes('mint') || lowerName.includes('claim');
        
        let hasSlippage = false;
        let hasDeadline = false;
        let hasLimits = false;
        
        // Проверяем параметры
        if (func.parameters) {
            const lowerParams = func.parameters.toLowerCase();
            if (lowerParams.includes('min') || lowerParams.includes('max') || 
                lowerParams.includes('slippage')) {
                hasSlippage = true;
            }
            if (lowerParams.includes('deadline')) {
                hasDeadline = true;
            }
            if (lowerParams.includes('limit') || lowerParams.includes('cap')) {
                hasLimits = true;
            }
        }
        
        // Проверяем тело
        if (func.body) {
            const lowerBody = func.body.toLowerCase();
            if (lowerBody.includes('min') || lowerBody.includes('max') || 
                lowerBody.includes('slippage')) {
                hasSlippage = true;
            }
            if (lowerBody.includes('deadline') || 
                (lowerBody.includes('block.timestamp') && lowerBody.includes('require'))) {
                hasDeadline = true;
            }
            if (lowerBody.includes('limit') || lowerBody.includes('cap') || 
                lowerBody.includes('only')) {
                hasLimits = true;
            }
        }
        
        // Вывод результатов
        if (isSwap && !hasSlippage) {
            findings.push("FRONT_RUNNING: Swap function lacks slippage protection");
        }
        if ((isSwap || isLiquidity) && !hasDeadline) {
            findings.push("FRONT_RUNNING: Function lacks deadline protection");
        }
        if (isMint && !hasLimits) {
            findings.push("FRONT_RUNNING: Mint/claim function lacks anti-sniping protection");
        }
        
        return findings;
    }

    // ---------- 5. TIMESTAMP DEPENDENCE (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkTimestampDependence(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (!func.body) return findings;
        
        // AST анализ для block.timestamp
        if (func.astNode && func.astNode.body) {
            ASTTraverser.traverse(func.astNode.body, {
                MemberAccess: (node) => {
                    if (node.expression && node.expression.name === 'block' && 
                        node.memberName === 'timestamp') {
                        
                        // Проверяем контекст использования
                        let parent = node.parent;
                        while (parent) {
                            if (parent.nodeType === 'BinaryOperation' && parent.operator === '%') {
                                findings.push("TIMESTAMP_DEPENDENCE: Using block.timestamp for randomness");
                                return;
                            }
                            
                            if (parent.nodeType === 'IfStatement' || 
                                (parent.nodeType === 'FunctionCall' && 
                                 parent.expression && 
                                 (parent.expression.name === 'require' || 
                                  parent.expression.name === 'assert'))) {
                                
                                const context = this.getSourceFromNode(parent, sourceCode).toLowerCase();
                                if (!context.includes('deadline')) {
                                    findings.push("TIMESTAMP_DEPENDENCE: Business logic depends on timestamp");
                                }
                                return;
                            }
                            parent = parent.parent;
                        }
                    }
                },
                
                Identifier: (node) => {
                    if (node.name === 'now') {
                        findings.push("TIMESTAMP_DEPENDENCE: Using deprecated 'now' keyword");
                    }
                }
            });
        }
        
        // Regex fallback
        if (findings.length === 0 && func.body) {
            const lowerBody = func.body.toLowerCase();
            
            if (lowerBody.includes('block.timestamp %') || 
                lowerBody.includes('block.timestamp &')) {
                findings.push("TIMESTAMP_DEPENDENCE: Using block.timestamp for randomness");
            }
            
            if (/block\.timestamp\s*[\+\-]\s*[1-5]/.test(lowerBody)) {
                findings.push("TIMESTAMP_DEPENDENCE: Small time window (< 5 seconds)");
            }
            
            if (lowerBody.includes('now')) {
                findings.push("TIMESTAMP_DEPENDENCE: Using deprecated 'now' keyword");
            }
        }
        
        return findings;
    }

    // ---------- 6. DELEGATECALL (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkDelegatecallVulnerabilities(func, sourceCode) {
        const findings = [];
        
        // AST анализ для delegatecall
        if (func.astNode && func.astNode.body) {
            ASTTraverser.traverse(func.astNode.body, {
                MemberAccess: (node) => {
                    if (node.memberName === 'delegatecall') {
                        findings.push("DELEGATECALL: Delegatecall found");
                        
                        // Проверяем user-controlled data
                        let parent = node.parent;
                        while (parent) {
                            if (parent.nodeType === 'FunctionCall' && 
                                parent.arguments && parent.arguments.length > 0) {
                                
                                const argsSrc = this.getSourceFromNode(parent.arguments[0], sourceCode);
                                if (argsSrc.includes('msg.data')) {
                                    findings.push("DELEGATECALL: User-controlled delegatecall with msg.data");
                                }
                            }
                            parent = parent.parent;
                        }
                    }
                }
            });
        }
        
        // Проверяем parity-style уязвимость
        if ((func.visibility === 'public' || func.visibility === 'external') && 
            func.parameters && func.parameters.includes('bytes')) {
            findings.push("DELEGATECALL: Public function with bytes parameter may allow arbitrary delegatecall");
        }
        
        // Regex fallback
        if (func.body && func.body.includes('delegatecall')) {
            if (!findings.includes("DELEGATECALL: Delegatecall found")) {
                findings.push("DELEGATECALL: Delegatecall found");
            }
            
            if (func.body.includes('msg.data')) {
                findings.push("DELEGATECALL: User-controlled delegatecall with msg.data");
            }
        }
        
        return findings;
    }

    // ---------- 7. UNCHECKED CALLS (ПОЛНАЯ РЕАЛИЗАЦИЯ) ----------
    static checkUncheckedCall(func, sourceCode) {
        const findings = [];
        
        if (this.isLibraryOrViewFunction(func)) return findings;
        if (!func.body) return findings;
        
        // AST анализ для вызовов
        if (func.astNode && func.astNode.body) {
            ASTTraverser.traverse(func.astNode.body, {
                FunctionCall: (node) => {
                    if (node.expression && node.expression.nodeType === 'MemberAccess') {
                        const ma = node.expression;
                        
                        if (ma.memberName === 'transfer' || ma.memberName === 'transferFrom') {
                            // Проверяем, есть ли проверка возвращаемого значения
                            let hasCheck = false;
                            let parent = node.parent;
                            
                            while (parent) {
                                if (parent.nodeType === 'IfStatement' || 
                                    (parent.nodeType === 'FunctionCall' && 
                                     parent.expression && 
                                     parent.expression.name === 'require')) {
                                    hasCheck = true;
                                    break;
                                }
                                parent = parent.parent;
                            }
                            
                            if (!hasCheck) {
                                findings.push(`UNCHECKED_CALL: ERC20 ${ma.memberName}() without return value check`);
                            }
                        }
                        
                        if (ma.memberName === 'send') {
                            let hasCheck = false;
                            let parent = node.parent;
                            
                            while (parent) {
                                if (parent.nodeType === 'IfStatement' || 
                                    (parent.nodeType === 'FunctionCall' && 
                                     parent.expression && 
                                     parent.expression.name === 'require')) {
                                    hasCheck = true;
                                    break;
                                }
                                parent = parent.parent;
                            }
                            
                            if (!hasCheck) {
                                findings.push("UNCHECKED_CALL: .send() without success check");
                            }
                        }
                    }
                }
            });
        }
        
        // Regex fallback
        if (func.body.includes('.transfer(') || func.body.includes('.transferFrom(')) {
            if (!func.body.includes('require') && !func.body.includes('if') && 
                !func.body.includes('assert')) {
                findings.push("UNCHECKED_CALL: ERC20 transfer/transferFrom without return value check");
            }
        }
        
        if (func.body.includes('.send(') && !func.body.includes('if') && 
            !func.body.includes('require')) {
            findings.push("UNCHECKED_CALL: .send() without success check");
        }
        
        if (func.body.includes('.call{') && !func.body.includes('success')) {
            findings.push("UNCHECKED_CALL: .call() without success check");
        }
        
        return findings;
    }

    // ---------- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ----------
    static getSourceFromNode(node, sourceCode) {
        if (!node || !node.src) return '';
        const [start, length] = node.src.split(':').map(Number);
        return sourceCode.substring(start, start + length);
    }
    
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
        const parser = SolidityParser;
        const checker = ProSecurityChecks;
        
        const { ast, pragma, functions } = parser.parse(srcText);
        
        const report = [];
        
        for (const f of functions) {
            const fFindings = [];
            
            // Пропускаем функции без тела
            if (!f.body || f.body.trim().length === 0) {
                if (f.name === '<constructor>' || f.name === 'fallback' || f.name === 'receive') {
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
    ProSecurityChecks,
    SolidityParser
};
