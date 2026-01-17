const parser = require('solidity-parser-antlr');
const { performance } = require('perf_hooks');

// ========== КОНСТАНТЫ И КОНФИГ ==========
const CONFIG = {
    MAX_ITERATIONS: 1000,
    MAX_FUNCTION_DEPTH: 20,
    MAX_CALL_GRAPH_SIZE: 500,
    TIMEOUT_MS: 30000,
    ENABLE_TAINT_ANALYSIS: true,
    ENABLE_SYMBOLIC_EXECUTION: true,
    ENABLE_INTERPROCEDURAL: true
};

const SECURITY_PATTERNS = {
    REENTRANCY: {
        HIGH_RISK: 3,
        MEDIUM_RISK: 2,
        LOW_RISK: 1
    },
    OVERFLOW: {
        HIGH_RISK: 3,
        MEDIUM_RISK: 2,
        LOW_RISK: 1
    }
};

// ========== ПРОДВИНУТЫЕ СТРУКТУРЫ ДАННЫХ ==========
class CallGraph {
    constructor() {
        this.nodes = new Map(); // functionName -> Node
        this.edges = new Map(); // caller -> [callees]
        this.cycles = new Set();
    }
    
    addFunction(funcName, astNode) {
        if (!this.nodes.has(funcName)) {
            this.nodes.set(funcName, {
                name: funcName,
                astNode,
                calledBy: new Set(),
                callsTo: new Set(),
                isRecursive: false,
                depth: 0,
                visited: false
            });
        }
        return this.nodes.get(funcName);
    }
    
    addCall(caller, callee) {
        const callerNode = this.nodes.get(caller);
        const calleeNode = this.nodes.get(callee);
        
        if (callerNode && calleeNode) {
            callerNode.callsTo.add(callee);
            calleeNode.calledBy.add(caller);
            
            if (!this.edges.has(caller)) {
                this.edges.set(caller, new Set());
            }
            this.edges.get(caller).add(callee);
        }
    }
    
    detectCycles() {
        const visited = new Set();
        const recursionStack = new Set();
        
        for (const [funcName, node] of this.nodes) {
            if (!visited.has(funcName)) {
                this._dfsDetectCycle(funcName, visited, recursionStack, []);
            }
        }
        
        return Array.from(this.cycles);
    }
    
    _dfsDetectCycle(node, visited, recursionStack, path) {
        visited.add(node);
        recursionStack.add(node);
        path.push(node);
        
        const edges = this.edges.get(node) || new Set();
        for (const neighbor of edges) {
            if (!visited.has(neighbor)) {
                this._dfsDetectCycle(neighbor, visited, recursionStack, [...path]);
            } else if (recursionStack.has(neighbor)) {
                // Найден цикл
                const cycleStart = path.indexOf(neighbor);
                const cycle = path.slice(cycleStart);
                this.cycles.add(JSON.stringify(cycle.sort()));
                
                // Помечаем функции как рекурсивные
                cycle.forEach(func => {
                    const node = this.nodes.get(func);
                    if (node) node.isRecursive = true;
                });
            }
        }
        
        recursionStack.delete(node);
    }
    
    getTransitiveClosure(funcName) {
        const closure = new Set();
        const stack = [funcName];
        
        while (stack.length > 0) {
            const current = stack.pop();
            if (!closure.has(current)) {
                closure.add(current);
                const edges = this.edges.get(current) || new Set();
                for (const neighbor of edges) {
                    stack.push(neighbor);
                }
            }
        }
        
        return closure;
    }
}

class SymbolicState {
    constructor() {
        this.variables = new Map(); // name -> SymbolicValue
        this.constraints = []; // [Constraint]
        this.pathConditions = []; // [Condition]
        this.storage = new Map(); // storageKey -> SymbolicValue
        this.memory = new Map(); // memoryKey -> SymbolicValue
        this.pc = 0; // program counter
    }
    
    clone() {
        const newState = new SymbolicState();
        newState.variables = new Map(this.variables);
        newState.constraints = [...this.constraints];
        newState.pathConditions = [...this.pathConditions];
        newState.storage = new Map(this.storage);
        newState.memory = new Map(this.memory);
        newState.pc = this.pc;
        return newState;
    }
    
    addConstraint(condition) {
        this.constraints.push(condition);
        this.pathConditions.push(condition);
        
        // Проверяем выполнимость
        if (!this.isSatisfiable()) {
            throw new Error('Unsatisfiable path');
        }
    }
    
    isSatisfiable() {
        // Простая проверка на противоречия
        const contradictions = [
            ['==', '!='],
            ['<', '>='],
            ['>', '<='],
            ['true', 'false']
        ];
        
        for (const [a, b] of contradictions) {
            if (this.constraints.includes(a) && this.constraints.includes(b)) {
                return false;
            }
        }
        
        return true;
    }
    
    getVariable(name) {
        if (this.variables.has(name)) {
            return this.variables.get(name);
        }
        
        // Создаём новую символическую переменную
        const symVar = new SymbolicValue(name);
        this.variables.set(name, symVar);
        return symVar;
    }
}

class SymbolicValue {
    constructor(name, value = null) {
        this.name = name;
        this.value = value;
        this.type = 'unknown';
        this.tainted = false;
        this.source = null;
        this.operations = [];
    }
    
    addOperation(op, operands) {
        this.operations.push({ op, operands, timestamp: Date.now() });
    }
    
    toString() {
        if (this.value !== null) return this.value.toString();
        return this.name;
    }
}

class TaintTracker {
    constructor() {
        this.sources = new Set([
            'msg.sender', 'msg.value', 'msg.data',
            'tx.origin', 'block.timestamp', 'block.number',
            'address(this).balance'
        ]);
        
        this.sinks = new Set([
            'call', 'delegatecall', 'staticcall', 'selfdestruct',
            'transfer', 'send', 'callcode'
        ]);
        
        this.taintedVars = new Map(); // varName -> {source, path}
        this.propagationRules = new Map();
    }
    
    markTainted(variable, source, path = []) {
        this.taintedVars.set(variable, {
            source,
            path: [...path, variable],
            timestamp: Date.now()
        });
    }
    
    isTainted(variable) {
        return this.taintedVars.has(variable);
    }
    
    propagateTaint(operation, operands, resultVar) {
        // Правила распространения
        const allTainted = operands.some(op => this.isTainted(op));
        if (allTainted) {
            this.markTainted(resultVar, 'propagation', operands);
            return true;
        }
        return false;
    }
    
    checkSinkUsage(node, context) {
        const sinksFound = [];
        
        for (const [varName, taintInfo] of this.taintedVars) {
            // Проверяем, используется ли заражённая переменная в опасной операции
            if (context.includes(varName)) {
                sinksFound.push({
                    variable: varName,
                    source: taintInfo.source,
                    path: taintInfo.path,
                    context: context
                });
            }
        }
        
        return sinksFound;
    }
}

// ========== РАСШИРЕННЫЙ ПАРСЕР С ПОЛНЫМ АНАЛИЗОМ ==========
class IndustrialParser {
    constructor(sourceCode) {
        this.sourceCode = sourceCode;
        this.ast = null;
        this.functions = new Map();
        this.modifiers = new Map();
        this.stateVariables = new Map();
        this.structs = new Map();
        this.enums = new Map();
        this.events = new Map();
        this.errors = new Map();
        this.callGraph = new CallGraph();
        this.taintTracker = new TaintTracker();
        this.contracts = new Map();
    }
    
    parse() {
        const startTime = performance.now();
        
        try {
            this.ast = parser.parse(this.sourceCode, {
                tolerant: true,
                range: true,
                loc: true,
                comments: true
            });
            
            // Полный анализ контракта
            this._attachParent(this.ast);
            this._extractGlobalDefinitions(this.ast);
            this._extractContracts(this.ast);
            this._extractAllFunctions();
            this._buildCallGraph();
            this._analyzeStorageLayout();
            this._analyzeInheritance();
            this._detectFunctionPatterns();
            
            const endTime = performance.now();
            console.log(`[Parser] Analysis completed in ${(endTime - startTime).toFixed(2)}ms`);
            
            return {
                success: true,
                ast: this.ast,
                functions: this.functions,
                callGraph: this.callGraph,
                contracts: this.contracts,
                stateVariables: this.stateVariables,
                stats: {
                    functions: this.functions.size,
                    contracts: this.contracts.size,
                    stateVars: this.stateVariables.size,
                    parseTime: endTime - startTime
                }
            };
            
        } catch (error) {
            console.error(`[Parser] Parse error: ${error.message}`);
            return {
                success: false,
                error: error.message,
                stack: error.stack
            };
        }
    }
    
    _attachParent(node, parent = null) {
        if (!node || typeof node !== 'object') return;
        
        node.parent = parent;
        
        for (const key in node) {
            if (key === 'parent' || key === 'range' || key === 'loc') continue;
            
            const child = node[key];
            if (Array.isArray(child)) {
                for (const item of child) {
                    if (item && typeof item === 'object') {
                        this._attachParent(item, node);
                    }
                }
            } else if (child && typeof child === 'object') {
                this._attachParent(child, node);
            }
        }
    }
    
    _extractGlobalDefinitions(ast) {
        if (!ast.children) return;
        
        const extractor = (node) => {
            if (!node) return;
            
            switch (node.type) {
                case 'StructDefinition':
                    this.structs.set(node.name, {
                        name: node.name,
                        members: node.members || [],
                        range: node.range
                    });
                    break;
                    
                case 'EnumDefinition':
                    this.enums.set(node.name, {
                        name: node.name,
                        members: node.members || [],
                        range: node.range
                    });
                    break;
                    
                case 'EventDefinition':
                    this.events.set(node.name, {
                        name: node.name,
                        parameters: node.parameters || [],
                        range: node.range
                    });
                    break;
                    
                case 'CustomErrorDefinition':
                    this.errors.set(node.name, {
                        name: node.name,
                        parameters: node.parameters || [],
                        range: node.range
                    });
                    break;
            }
            
            for (const key in node) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(extractor);
                } else if (child && typeof child === 'object') {
                    extractor(child);
                }
            }
        };
        
        extractor(ast);
    }
    
    _extractContracts(ast) {
        if (!ast.children) return;
        
        for (const child of ast.children) {
            if (child.type === 'ContractDefinition') {
                const contractInfo = {
                    name: child.name,
                    kind: child.kind, // contract, interface, library
                    baseContracts: child.baseContracts || [],
                    nodes: child.subNodes || [],
                    range: child.range,
                    functions: new Map(),
                    stateVariables: new Map(),
                    modifiers: new Map()
                };
                
                // Извлекаем state variables
                if (child.subNodes) {
                    for (const node of child.subNodes) {
                        if (node.type === 'StateVariableDeclaration') {
                            if (node.variables && node.variables.length > 0) {
                                const varNode = node.variables[0];
                                const varInfo = {
                                    name: varNode.name,
                                    type: this._getTypeName(varNode.typeName),
                                    visibility: varNode.visibility || 'default',
                                    isConstant: varNode.isDeclaredConst || false,
                                    isImmutable: varNode.isImmutable || false,
                                    initialValue: varNode.expression,
                                    range: varNode.range
                                };
                                
                                contractInfo.stateVariables.set(varNode.name, varInfo);
                                this.stateVariables.set(`${child.name}.${varNode.name}`, varInfo);
                            }
                        } else if (node.type === 'ModifierDefinition') {
                            contractInfo.modifiers.set(node.name, node);
                        }
                    }
                }
                
                this.contracts.set(child.name, contractInfo);
            }
        }
    }
    
    _extractAllFunctions() {
        for (const [contractName, contract] of this.contracts) {
            this._extractFunctionsFromNode(contract.nodes, contractName);
        }
    }
    
    _extractFunctionsFromNode(nodes, contractName, parentNode = null) {
        if (!nodes) return;
        
        for (const node of nodes) {
            if (node.type === 'FunctionDefinition') {
                const funcName = node.name || (node.isConstructor ? 'constructor' : 
                              node.isFallback ? 'fallback' : 
                              node.isReceiveEther ? 'receive' : 'unnamed');
                
                const fullName = `${contractName}.${funcName}`;
                
                const funcInfo = {
                    id: fullName,
                    name: funcName,
                    contract: contractName,
                    astNode: node,
                    parameters: node.parameters || { parameters: [] },
                    returnParameters: node.returnParameters || { parameters: [] },
                    body: node.body,
                    visibility: node.visibility || 'default',
                    stateMutability: node.stateMutability || 'nonpayable',
                    modifiers: node.modifiers || [],
                    isConstructor: node.isConstructor || false,
                    isFallback: node.isFallback || false,
                    isReceiveEther: node.isReceiveEther || false,
                    isVirtual: node.isVirtual || false,
                    isOverride: node.override || false,
                    range: node.range,
                    parentNode: parentNode
                };
                
                this.functions.set(fullName, funcInfo);
                contract.functions.set(funcName, funcInfo);
                
                // Анализ тела функции
                if (node.body) {
                    this._analyzeFunctionBody(node.body, fullName);
                }
            }
            
            // Рекурсивный обход
            for (const key in node) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    this._extractFunctionsFromNode(child, contractName, node);
                } else if (child && typeof child === 'object') {
                    this._extractFunctionsFromNode([child], contractName, node);
                }
            }
        }
    }
    
    _analyzeFunctionBody(bodyNode, functionName) {
        // Анализ control flow
        const cfg = this._buildControlFlowGraph(bodyNode);
        
        // Анализ data flow
        const df = this._analyzeDataFlow(bodyNode);
        
        // Анализ использования storage/memory
        const storageAccess = this._analyzeStorageAccess(bodyNode);
        
        // Добавляем информацию к функции
        const funcInfo = this.functions.get(functionName);
        if (funcInfo) {
            funcInfo.cfg = cfg;
            funcInfo.dataFlow = df;
            funcInfo.storageAccess = storageAccess;
            funcInfo.hasExternalCalls = this._hasExternalCalls(bodyNode);
            funcInfo.hasStateChanges = this._hasStateChanges(bodyNode);
            funcInfo.hasLoops = this._hasLoops(bodyNode);
        }
    }
    
    _buildControlFlowGraph(bodyNode) {
        const blocks = [];
        const edges = [];
        let currentBlock = [];
        
        const visitor = (node) => {
            if (!node) return;
            
            // Конец базового блока
            const isTerminator = [
                'IfStatement', 'ReturnStatement', 'BreakStatement',
                'ContinueStatement', 'ThrowStatement', 'RevertStatement'
            ].includes(node.type);
            
            if (isTerminator && currentBlock.length > 0) {
                blocks.push([...currentBlock]);
                currentBlock = [];
            }
            
            currentBlock.push({
                type: node.type,
                range: node.range,
                loc: node.loc
            });
            
            // Обрабатываем детей
            for (const key in node) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
            
            if (isTerminator && currentBlock.length > 0) {
                blocks.push([...currentBlock]);
                currentBlock = [];
            }
        };
        
        visitor(bodyNode);
        
        if (currentBlock.length > 0) {
            blocks.push(currentBlock);
        }
        
        // Строим граф переходов между блоками
        for (let i = 0; i < blocks.length - 1; i++) {
            edges.push([i, i + 1]);
        }
        
        return { blocks, edges };
    }
    
    _analyzeDataFlow(bodyNode) {
        const defs = new Map(); // variable -> [definitionNodes]
        const uses = new Map(); // variable -> [useNodes]
        const reachingDefs = new Map(); // node -> [definitions]
        
        const visitor = (node) => {
            if (!node) return;
            
            switch (node.type) {
                case 'VariableDeclaration':
                    if (node.name) {
                        if (!defs.has(node.name)) defs.set(node.name, []);
                        defs.get(node.name).push(node);
                    }
                    break;
                    
                case 'Identifier':
                    if (node.name && !this._isReservedWord(node.name)) {
                        if (!uses.has(node.name)) uses.set(node.name, []);
                        uses.get(node.name).push(node);
                    }
                    break;
                    
                case 'Assignment':
                    if (node.left && node.left.name) {
                        if (!defs.has(node.left.name)) defs.set(node.left.name, []);
                        defs.get(node.left.name).push(node);
                    }
                    break;
            }
            
            for (const key in node) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(bodyNode);
        
        return { defs, uses, reachingDefs };
    }
    
    _analyzeStorageAccess(bodyNode) {
        const accesses = {
            reads: [],
            writes: [],
            mappings: [],
            arrays: []
        };
        
        const visitor = (node) => {
            if (!node) return;
            
            // Анализ доступа к storage
            if (node.type === 'MemberAccess') {
                const expr = this._getSource(node.expression);
                if (expr.includes('this') || expr.includes('storage')) {
                    accesses.reads.push({
                        expression: this._getSource(node),
                        node: node,
                        range: node.range
                    });
                }
            } else if (node.type === 'IndexAccess') {
                accesses.arrays.push({
                    expression: this._getSource(node),
                    node: node,
                    range: node.range
                });
            } else if (node.type === 'Assignment') {
                const leftSrc = this._getSource(node.left);
                if (leftSrc.includes('.') || leftSrc.includes('[')) {
                    accesses.writes.push({
                        expression: leftSrc,
                        node: node,
                        range: node.range
                    });
                }
            }
            
            for (const key in node) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(bodyNode);
        return accesses;
    }
    
    _buildCallGraph() {
        for (const [funcName, funcInfo] of this.functions) {
            this.callGraph.addFunction(funcName, funcInfo.astNode);
            
            // Находим все вызовы в теле функции
            if (funcInfo.body) {
                const callees = this._extractFunctionCalls(funcInfo.body);
                for (const callee of callees) {
                    this.callGraph.addCall(funcName, callee);
                }
            }
        }
        
        // Обнаружение циклов
        this.callGraph.detectCycles();
        
        // Вычисление глубины вызовов
        for (const [funcName, node] of this.callGraph.nodes) {
            node.depth = this._calculateCallDepth(funcName);
        }
    }
    
    _extractFunctionCalls(node, calls = new Set()) {
        if (!node) return calls;
        
        if (node.type === 'FunctionCall') {
            if (node.expression.type === 'Identifier') {
                calls.add(node.expression.name);
            } else if (node.expression.type === 'MemberAccess') {
                // Обрабатываем вызовы вида contract.function()
                const fullCall = this._getSource(node.expression);
                calls.add(fullCall);
            }
        }
        
        for (const key in node) {
            if (key === 'parent' || key === 'range' || key === 'loc') continue;
            const child = node[key];
            if (Array.isArray(child)) {
                for (const item of child) {
                    this._extractFunctionCalls(item, calls);
                }
            } else if (child && typeof child === 'object') {
                this._extractFunctionCalls(child, calls);
            }
        }
        
        return calls;
    }
    
    _calculateCallDepth(funcName, visited = new Set(), depth = 0) {
        if (visited.has(funcName)) {
            return depth; // Рекурсия
        }
        
        visited.add(funcName);
        let maxDepth = depth;
        const edges = this.callGraph.edges.get(funcName) || new Set();
        
        for (const callee of edges) {
            const calleeDepth = this._calculateCallDepth(callee, new Set(visited), depth + 1);
            if (calleeDepth > maxDepth) {
                maxDepth = calleeDepth;
            }
        }
        
        return maxDepth;
    }
    
    _analyzeStorageLayout() {
        for (const [contractName, contract] of this.contracts) {
            let slot = 0;
            for (const [varName, varInfo] of contract.stateVariables) {
                varInfo.storageSlot = slot;
                slot += this._calculateStorageSize(varInfo.type);
            }
        }
    }
    
    _analyzeInheritance() {
        for (const [contractName, contract] of this.contracts) {
            const inheritanceChain = this._resolveInheritance(contract);
            contract.inheritanceChain = inheritanceChain;
            contract.isBaseContract = inheritanceChain.length === 0;
            
            // Проверяем linearization
            const linearization = this._c3Linearization(contract);
            contract.linearization = linearization;
        }
    }
    
    _resolveInheritance(contract, chain = []) {
        for (const base of contract.baseContracts) {
            const baseName = base.baseName.namePath;
            const baseContract = this.contracts.get(baseName);
            if (baseContract) {
                chain.push(baseName);
                this._resolveInheritance(baseContract, chain);
            }
        }
        return chain;
    }
    
    _c3Linearization(contract) {
        // Алгоритм C3 linearization для наследования
        const results = [contract.name];
        
        for (const base of contract.baseContracts) {
            const baseName = base.baseName.namePath;
            const baseContract = this.contracts.get(baseName);
            if (baseContract) {
                results.push(...this._c3Linearization(baseContract));
            }
        }
        
        return [...new Set(results)];
    }
    
    _detectFunctionPatterns() {
        for (const [funcName, funcInfo] of this.functions) {
            // Определяем шаблоны функций
            const patterns = [];
            
            if (this._isERC20Transfer(funcInfo)) patterns.push('ERC20_TRANSFER');
            if (this._isERC20Approve(funcInfo)) patterns.push('ERC20_APPROVE');
            if (this._isERC721SafeTransfer(funcInfo)) patterns.push('ERC721_SAFE_TRANSFER');
            if (this._isOwnable(funcInfo)) patterns.push('OWNABLE');
            if (this._isPausable(funcInfo)) patterns.push('PAUSABLE');
            if (this._isReentrancyGuard(funcInfo)) patterns.push('REENTRANCY_GUARD');
            if (this._isAccessControl(funcInfo)) patterns.push('ACCESS_CONTROL');
            
            funcInfo.patterns = patterns;
        }
    }
    
    _isERC20Transfer(funcInfo) {
        const sig = this._getSource(funcInfo.astNode).toLowerCase();
        return (funcInfo.name === 'transfer' || funcInfo.name === 'transferFrom') &&
               sig.includes('returns (bool)') &&
               sig.includes('address') &&
               sig.includes('uint256');
    }
    
    _isERC20Approve(funcInfo) {
        const sig = this._getSource(funcInfo.astNode).toLowerCase();
        return funcInfo.name === 'approve' &&
               sig.includes('returns (bool)') &&
               sig.includes('address') &&
               sig.includes('uint256');
    }
    
    _isOwnable(funcInfo) {
        const sig = this._getSource(funcInfo.astNode).toLowerCase();
        return (funcInfo.name === 'transferOwnership' || 
                funcInfo.name === 'renounceOwnership') &&
               sig.includes('onlyOwner');
    }
    
    // Вспомогательные методы
    _getSource(node) {
        if (!node || !node.range) return '';
        const [start, length] = node.range;
        return this.sourceCode.substring(start, start + length);
    }
    
    _getTypeName(typeNode) {
        if (!typeNode) return 'unknown';
        
        if (typeNode.type === 'ElementaryTypeName') {
            return typeNode.name;
        } else if (typeNode.type === 'UserDefinedTypeName') {
            return typeNode.namePath;
        } else if (typeNode.type === 'ArrayTypeName') {
            const baseType = this._getTypeName(typeNode.baseTypeName);
            const size = typeNode.length ? this._getSource(typeNode.length) : '';
            return `${baseType}[${size}]`;
        } else if (typeNode.type === 'Mapping') {
            const keyType = this._getTypeName(typeNode.keyType);
            const valueType = this._getTypeName(typeNode.valueType);
            return `mapping(${keyType} => ${valueType})`;
        }
        
        return 'unknown';
    }
    
    _calculateStorageSize(typeName) {
        if (typeName.startsWith('uint') || typeName.startsWith('int')) {
            return 1;
        } else if (typeName.startsWith('bytes')) {
            const match = typeName.match(/bytes(\d+)/);
            if (match) {
                const size = parseInt(match[1]);
                return Math.ceil(size / 32);
            }
            return 1;
        } else if (typeName === 'address' || typeName === 'bool') {
            return 1;
        } else if (typeName.includes('[')) {
            // Массив - сложный расчёт
            return 1; // Упрощённо
        } else if (typeName.includes('mapping')) {
            return 1;
        }
        return 1;
    }
    
    _hasExternalCalls(node) {
        if (!node) return false;
        
        let hasCalls = false;
        const visitor = (n) => {
            if (n.type === 'FunctionCall' && n.expression.type === 'MemberAccess') {
                const expr = n.expression;
                if (expr.memberName === 'call' || expr.memberName === 'delegatecall' || 
                    expr.memberName === 'staticcall' || expr.memberName === 'transfer' || 
                    expr.memberName === 'send') {
                    hasCalls = true;
                }
            }
            
            for (const key in n) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = n[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(node);
        return hasCalls;
    }
    
    _hasStateChanges(node) {
        if (!node) return false;
        
        let hasChanges = false;
        const visitor = (n) => {
            if (n.type === 'Assignment') {
                const leftSrc = this._getSource(n.left).toLowerCase();
                if (leftSrc.includes('balance') || leftSrc.includes('.') || 
                    leftSrc.includes('[') || leftSrc.includes('total')) {
                    hasChanges = true;
                }
            } else if (n.type === 'UnaryOperation' && (n.operator === '++' || n.operator === '--')) {
                hasChanges = true;
            }
            
            for (const key in n) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = n[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(node);
        return hasChanges;
    }
    
    _hasLoops(node) {
        if (!node) return false;
        
        let hasLoops = false;
        const visitor = (n) => {
            if (n.type === 'ForStatement' || n.type === 'WhileStatement' || 
                n.type === 'DoWhileStatement') {
                hasLoops = true;
            }
            
            for (const key in n) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = n[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(node);
        return hasLoops;
    }
    
    _isReservedWord(name) {
        const reserved = [
            'msg', 'block', 'tx', 'abi', 'assert', 'require',
            'revert', 'this', 'super', 'now', 'gasleft'
        ];
        return reserved.includes(name);
    }
}

// ========== СИМВОЛИЧЕСКОЕ ИСПОЛНЕНИЕ ==========
class SymbolicExecutor {
    constructor(parser, functionName) {
        this.parser = parser;
        this.functionName = functionName;
        this.funcInfo = parser.functions.get(functionName);
        this.states = [new SymbolicState()];
        this.visitedPaths = new Set();
        this.results = [];
        this.timeout = CONFIG.TIMEOUT_MS;
        this.startTime = performance.now();
    }
    
    execute() {
        if (!this.funcInfo || !this.funcInfo.body) {
            return { success: false, error: 'Function not found or has no body' };
        }
        
        try {
            this._executeNode(this.funcInfo.body, this.states[0]);
            
            return {
                success: true,
                results: this.results,
                pathsExplored: this.visitedPaths.size,
                states: this.states.length,
                executionTime: performance.now() - this.startTime
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                stack: error.stack
            };
        }
    }
    
    _executeNode(node, state) {
        if (performance.now() - this.startTime > this.timeout) {
            throw new Error('Symbolic execution timeout');
        }
        
        if (this.visitedPaths.size > CONFIG.MAX_ITERATIONS) {
            throw new Error('Maximum iterations reached');
        }
        
        const pathId = this._getPathId(state);
        if (this.visitedPaths.has(pathId)) {
            return; // Уже посещали этот путь
        }
        this.visitedPaths.add(pathId);
        
        switch (node.type) {
            case 'Block':
                this._executeBlock(node, state);
                break;
                
            case 'ExpressionStatement':
                this._executeExpression(node.expression, state);
                break;
                
            case 'VariableDeclarationStatement':
                this._executeVariableDeclaration(node, state);
                break;
                
            case 'IfStatement':
                this._executeIfStatement(node, state);
                break;
                
            case 'ReturnStatement':
                this._executeReturn(node, state);
                break;
                
            case 'ForStatement':
                this._executeForStatement(node, state);
                break;
                
            case 'WhileStatement':
            case 'DoWhileStatement':
                this._executeWhileStatement(node, state);
                break;
                
            case 'FunctionCall':
                this._executeFunctionCall(node, state);
                break;
                
            case 'Assignment':
                this._executeAssignment(node, state);
                break;
                
            case 'BinaryOperation':
                this._executeBinaryOperation(node, state);
                break;
                
            case 'UnaryOperation':
                this._executeUnaryOperation(node, state);
                break;
                
            default:
                // Рекурсивно выполняем детей
                for (const key in node) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = node[key];
                    if (Array.isArray(child)) {
                        for (const item of child) {
                            if (item && typeof item === 'object') {
                                this._executeNode(item, state);
                            }
                        }
                    } else if (child && typeof child === 'object') {
                        this._executeNode(child, state);
                    }
                }
        }
    }
    
    _executeBlock(block, state) {
        if (block.statements) {
            for (const stmt of block.statements) {
                this._executeNode(stmt, state);
            }
        }
    }
    
    _executeIfStatement(ifStmt, state) {
        // Создаём две ветки: then и else
        const thenState = state.clone();
        const elseState = state.clone();
        
        // Вычисляем условие
        const condition = this._evaluateExpression(ifStmt.condition, state);
        
        // Добавляем условие к соответствующим состояниям
        thenState.addConstraint(condition);
        elseState.addConstraint(`!(${condition})`);
        
        // Выполняем then ветку
        if (ifStmt.trueBody) {
            this._executeNode(ifStmt.trueBody, thenState);
        }
        
        // Выполняем else ветку если есть
        if (ifStmt.falseBody) {
            this._executeNode(ifStmt.falseBody, elseState);
        }
        
        // Объединяем состояния
        this.states = this.states.filter(s => s !== state);
        this.states.push(thenState, elseState);
    }
    
    _executeVariableDeclaration(decl, state) {
        if (decl.variables && decl.variables.length > 0) {
            for (const variable of decl.variables) {
                if (variable.name) {
                    let value = 'unknown';
                    if (decl.initialValue) {
                        value = this._evaluateExpression(decl.initialValue, state);
                    }
                    
                    const symVar = new SymbolicValue(variable.name, value);
                    state.variables.set(variable.name, symVar);
                    
                    // Проверяем taint sources
                    const source = this._getSource(decl.initialValue);
                    if (source && this._isTaintSource(source)) {
                        this.parser.taintTracker.markTainted(variable.name, source);
                        symVar.tainted = true;
                        symVar.source = source;
                    }
                }
            }
        }
    }
    
    _executeFunctionCall(call, state) {
        const funcName = call.expression.type === 'Identifier' ? 
                         call.expression.name : 
                         this.parser._getSource(call.expression);
        
        // Проверяем опасные вызовы
        if (call.expression.type === 'MemberAccess') {
            const memberName = call.expression.memberName;
            
            if (memberName === 'call' || memberName === 'delegatecall' || 
                memberName === 'staticcall') {
                
                // Проверяем taint analysis
                if (call.arguments && call.arguments.length > 0) {
                    for (const arg of call.arguments) {
                        const argValue = this._evaluateExpression(arg, state);
                        if (state.variables.has(argValue)) {
                            const varInfo = state.variables.get(argValue);
                            if (varInfo.tainted) {
                                this.results.push({
                                    type: 'TAINTED_CALL',
                                    severity: 'HIGH',
                                    message: `Tainted data used in ${memberName}`,
                                    function: this.functionName,
                                    variable: argValue,
                                    source: varInfo.source
                                });
                            }
                        }
                    }
                }
                
                // Проверяем unchecked calls
                const context = this._getCallContext(call);
                if (!this._hasSuccessCheck(call, context)) {
                    this.results.push({
                        type: 'UNCHECKED_CALL',
                        severity: 'MEDIUM',
                        message: `${memberName} without success check`,
                        function: this.functionName,
                        context: context
                    });
                }
            }
        }
        
        // Рекурсивно анализируем аргументы
        if (call.arguments) {
            for (const arg of call.arguments) {
                this._executeNode(arg, state);
            }
        }
    }
    
    _executeAssignment(assign, state) {
        const left = this._evaluateExpression(assign.left, state);
        const right = this._evaluateExpression(assign.right, state);
        
        // Проверяем переполнение для арифметических операций
        if (assign.operator && assign.operator !== '=') {
            this._checkOverflow(left, right, assign.operator, state);
        }
        
        // Обновляем значение переменной
        if (assign.left.type === 'Identifier') {
            const varName = assign.left.name;
            const symVar = state.getVariable(varName);
            symVar.value = right;
            symVar.addOperation(assign.operator || '=', [left, right]);
            
            // Проверяем taint propagation
            if (state.variables.has(right)) {
                const rightVar = state.variables.get(right);
                if (rightVar.tainted) {
                    this.parser.taintTracker.markTainted(varName, rightVar.source);
                    symVar.tainted = true;
                    symVar.source = rightVar.source;
                }
            }
        }
    }
    
    _executeBinaryOperation(binOp, state) {
        const left = this._evaluateExpression(binOp.left, state);
        const right = this._evaluateExpression(binOp.right, state);
        
        this._checkOverflow(left, right, binOp.operator, state);
        
        return `${left} ${binOp.operator} ${right}`;
    }
    
    _checkOverflow(left, right, operator, state) {
        // Проверяем возможное переполнение для целочисленных операций
        if (['+', '-', '*', '/', '**', '<<', '>>'].includes(operator)) {
            const context = this._getNodeContext(state.pc);
            
            // Проверяем unchecked блоки
            let currentNode = state.pc;
            let inUnchecked = false;
            while (currentNode) {
                if (currentNode.type === 'UncheckedStatement') {
                    inUnchecked = true;
                    break;
                }
                currentNode = currentNode.parent;
            }
            
            if (!inUnchecked) {
                const version = this._getSolidityVersion();
                const builtinSafe = versionGe(parseVersionFromPragma(version), [0, 8, 0]);
                
                if (!builtinSafe) {
                    this.results.push({
                        type: 'POTENTIAL_OVERFLOW',
                        severity: 'MEDIUM',
                        message: `Arithmetic operation '${left} ${operator} ${right}' without overflow protection`,
                        function: this.functionName,
                        context: context
                    });
                }
            }
        }
    }
    
    // Вспомогательные методы
    _evaluateExpression(expr, state) {
        if (!expr) return 'unknown';
        
        switch (expr.type) {
            case 'Identifier':
                if (state.variables.has(expr.name)) {
                    const varInfo = state.variables.get(expr.name);
                    return varInfo.value || expr.name;
                }
                return expr.name;
                
            case 'Literal':
                return expr.value;
                
            case 'MemberAccess':
                const object = this._evaluateExpression(expr.expression, state);
                const member = expr.memberName;
                return `${object}.${member}`;
                
            case 'BinaryOperation':
                return this._executeBinaryOperation(expr, state);
                
            case 'UnaryOperation':
                const operand = this._evaluateExpression(expr.subExpression, state);
                return `${expr.operator}${operand}`;
                
            case 'FunctionCall':
                return `CALL(${expr.expression.name})`;
                
            default:
                return 'unknown';
        }
    }
    
    _getPathId(state) {
        // Создаём уникальный идентификатор пути
        const vars = Array.from(state.variables.entries())
            .map(([k, v]) => `${k}=${v.value}`)
            .sort()
            .join('|');
        
        const constraints = state.constraints.sort().join('|');
        
        return `${vars}|${constraints}|${state.pc}`;
    }
    
    _getCallContext(node) {
        const source = this.parser._getSource(node);
        const lines = source.split('\n');
        return lines.length > 0 ? lines[0].trim() : '';
    }
    
    _getNodeContext(pc) {
        return `PC: ${pc}`;
    }
    
    _getSolidityVersion() {
        // Ищем pragma в AST
        const findPragma = (node) => {
            if (node.type === 'PragmaDirective' && node.name === 'solidity') {
                return node.value;
            }
            for (const key in node) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    for (const item of child) {
                        const result = findPragma(item);
                        if (result) return result;
                    }
                } else if (child && typeof child === 'object') {
                    const result = findPragma(child);
                    if (result) return result;
                }
            }
            return null;
        };
        
        return findPragma(this.parser.ast);
    }
    
    _hasSuccessCheck(callNode, context) {
        // Ищем проверки успеха после вызова
        let parent = callNode.parent;
        while (parent) {
            if (parent.type === 'IfStatement') {
                const condition = this.parser._getSource(parent.condition).toLowerCase();
                if (condition.includes('success') || condition.includes('ok') || 
                    condition.includes('require') || condition.includes('assert')) {
                    return true;
                }
            } else if (parent.type === 'FunctionCall' && parent.expression) {
                const funcName = parent.expression.name || '';
                if (funcName.toLowerCase() === 'require' || funcName.toLowerCase() === 'assert') {
                    const args = this.parser._getSource(parent).toLowerCase();
                    if (args.includes('success') || args.includes('ok')) {
                        return true;
                    }
                }
            }
            parent = parent.parent;
        }
        
        // Проверяем контекст
        if (context.toLowerCase().includes('require') || 
            context.toLowerCase().includes('assert') ||
            context.toLowerCase().includes('if')) {
            return true;
        }
        
        return false;
    }
    
    _isTaintSource(source) {
        const taintSources = [
            'msg.sender', 'msg.value', 'msg.data',
            'tx.origin', 'block.timestamp',
            'address.call', 'external'
        ];
        
        return taintSources.some(ts => source.toLowerCase().includes(ts));
    }
}

// ========== МЕЖПРОЦЕДУРНЫЙ АНАЛИЗАТОР ==========
class InterproceduralAnalyzer {
    constructor(parser) {
        this.parser = parser;
        this.callGraph = parser.callGraph;
        this.results = [];
        this.analyzedFunctions = new Set();
    }
    
    analyzeReentrancy() {
        console.log('[Interprocedural] Analyzing reentrancy vulnerabilities...');
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (this.analyzedFunctions.has(funcName)) continue;
            
            if (funcInfo.hasExternalCalls && funcInfo.hasStateChanges) {
                this._analyzeFunctionReentrancy(funcName);
            }
        }
        
        return this.results;
    }
    
    _analyzeFunctionReentrancy(funcName) {
        const funcInfo = this.parser.functions.get(funcName);
        if (!funcInfo || !funcInfo.body) return;
        
        // Находим все внешние вызовы
        const externalCalls = this._findExternalCalls(funcInfo.body);
        const stateChanges = this._findStateChanges(funcInfo.body);
        
        // Проверяем CEI violation
        for (const call of externalCalls) {
            for (const change of stateChanges) {
                if (call.pos < change.pos) {
                    // Проверяем, есть ли проверка между ними
                    const betweenCode = this.parser.sourceCode.substring(call.pos, change.pos);
                    const hasCheck = this._hasSecurityCheck(betweenCode);
                    
                    if (!hasCheck) {
                        // Межпроцедурный анализ: проверяем, может ли вызов вызвать рекурсию
                        const canReenter = this._canFunctionReenter(call.callee, funcName);
                        
                        if (canReenter) {
                            this.results.push({
                                type: 'REENTRANCY',
                                severity: 'HIGH',
                                message: `Reentrancy vulnerability: external call before state update`,
                                function: funcName,
                                call: call,
                                stateChange: change,
                                reentrancyPath: canReenter,
                                line: this._getLineNumber(call.pos)
                            });
                        }
                    }
                }
            }
        }
    }
    
    _findExternalCalls(node) {
        const calls = [];
        
        const visitor = (n) => {
            if (n.type === 'FunctionCall' && n.expression.type === 'MemberAccess') {
                const ma = n.expression;
                if (ma.memberName === 'call' || ma.memberName === 'delegatecall' || 
                    ma.memberName === 'staticcall' || ma.memberName === 'transfer' || 
                    ma.memberName === 'send') {
                    
                    calls.push({
                        type: ma.memberName,
                        pos: n.range[0],
                        callee: this.parser._getSource(n),
                        node: n
                    });
                }
            }
            
            for (const key in n) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = n[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(node);
        return calls;
    }
    
    _findStateChanges(node) {
        const changes = [];
        
        const visitor = (n) => {
            if (n.type === 'Assignment') {
                const leftSrc = this.parser._getSource(n.left);
                if (this._isStateVariable(leftSrc) || this._isStorageAccess(leftSrc)) {
                    changes.push({
                        type: 'ASSIGNMENT',
                        pos: n.range[0],
                        variable: leftSrc,
                        node: n
                    });
                }
            } else if (n.type === 'UnaryOperation' && (n.operator === '++' || n.operator === '--')) {
                const exprSrc = this.parser._getSource(n.subExpression);
                if (this._isStateVariable(exprSrc)) {
                    changes.push({
                        type: 'INCREMENT_DECREMENT',
                        pos: n.range[0],
                        variable: exprSrc,
                        node: n
                    });
                }
            }
            
            for (const key in n) {
                if (key === 'parent' || key === 'range' || key === 'loc') continue;
                const child = n[key];
                if (Array.isArray(child)) {
                    child.forEach(visitor);
                } else if (child && typeof child === 'object') {
                    visitor(child);
                }
            }
        };
        
        visitor(node);
        return changes;
    }
    
    _isStateVariable(expr) {
        if (!expr) return false;
        
        // Проверяем, является ли выражение state variable
        for (const [fullName, varInfo] of this.parser.stateVariables) {
            if (expr.includes(varInfo.name)) {
                return true;
            }
        }
        
        // Проверяем доступ через this
        if (expr.includes('this.') || expr.includes('balance[') || 
            expr.includes('[') && expr.includes(']')) {
            return true;
        }
        
        return false;
    }
    
    _isStorageAccess(expr) {
        return expr.includes('.') || expr.includes('[') && expr.includes(']');
    }
    
    _hasSecurityCheck(code) {
        const checks = ['require(', 'assert(', 'if (', 'revert '];
        return checks.some(check => code.includes(check));
    }
    
    _canFunctionReenter(callExpr, callerFunc) {
        // Находим, какую функцию вызывает callExpr
        const calledFunc = this._resolveFunctionCall(callExpr);
        if (!calledFunc) return false;
        
        // Проверяем, может ли вызванная функция вызвать обратно callerFunc
        const transitiveClosure = this.callGraph.getTransitiveClosure(calledFunc);
        return transitiveClosure.has(callerFunc);
    }
    
    _resolveFunctionCall(callExpr) {
        // Упрощённая реализация разрешения вызова функции
        // В реальной реализации нужно учитывать contract.function()
        const match = callExpr.match(/(\w+)\.(\w+)/);
        if (match) {
            const [, contract, func] = match;
            return `${contract}.${func}`;
        }
        
        // Простое имя функции
        const funcName = callExpr.split('(')[0].trim();
        for (const [fullName, funcInfo] of this.parser.functions) {
            if (funcInfo.name === funcName) {
                return fullName;
            }
        }
        
        return null;
    }
    
    _getLineNumber(pos) {
        const code = this.parser.sourceCode.substring(0, pos);
        return code.split('\n').length;
    }
}

// ========== ГЛАВНЫЙ АНАЛИЗАТОР ==========
class IndustrialSecurityScanner {
    constructor(sourceCode, options = {}) {
        this.sourceCode = sourceCode;
        this.options = { ...CONFIG, ...options };
        this.parser = null;
        this.results = {
            vulnerabilities: [],
            warnings: [],
            info: [],
            stats: {}
        };
        this.startTime = performance.now();
    }
    
    scan() {
        console.log('[Scanner] Starting industrial security scan...');
        
        try {
            // Шаг 1: Парсинг и базовый анализ
            this.parser = new IndustrialParser(this.sourceCode);
            const parseResult = this.parser.parse();
            
            if (!parseResult.success) {
                throw new Error(`Parse failed: ${parseResult.error}`);
            }
            
            this.results.stats.parsing = parseResult.stats;
            
            // Шаг 2: Межпроцедурный анализ
            if (this.options.ENABLE_INTERPROCEDURAL) {
                const interAnalyzer = new InterproceduralAnalyzer(this.parser);
                const reentrancyResults = interAnalyzer.analyzeReentrancy();
                this.results.vulnerabilities.push(...reentrancyResults);
            }
            
            // Шаг 3: Символическое исполнение для критических функций
            if (this.options.ENABLE_SYMBOLIC_EXECUTION) {
                this._runSymbolicExecution();
            }
            
            // Шаг 4: Статические проверки
            this._runStaticChecks();
            
            // Шаг 5: Taint analysis
            if (this.options.ENABLE_TAINT_ANALYSIS) {
                this._runTaintAnalysis();
            }
            
            // Шаг 6: Паттерн-матчинг
            this._runPatternMatching();
            
            // Финализация
            this.results.stats.totalTime = performance.now() - this.startTime;
            this.results.stats.functionsAnalyzed = this.parser.functions.size;
            this.results.stats.vulnerabilitiesFound = this.results.vulnerabilities.length;
            this.results.stats.warningsFound = this.results.warnings.length;
            
            console.log(`[Scanner] Scan completed in ${this.results.stats.totalTime.toFixed(2)}ms`);
            console.log(`[Scanner] Found ${this.results.vulnerabilities.length} vulnerabilities, ${this.results.warnings.length} warnings`);
            
            return {
                success: true,
                results: this.results,
                parser: this.parser
            };
            
        } catch (error) {
            console.error(`[Scanner] Scan failed: ${error.message}`);
            return {
                success: false,
                error: error.message,
                stack: error.stack,
                results: this.results
            };
        }
    }
    
    _runSymbolicExecution() {
        console.log('[Scanner] Running symbolic execution...');
        
        // Запускаем символическое исполнение для функций с external calls
        let analyzed = 0;
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (funcInfo.hasExternalCalls || funcInfo.hasStateChanges) {
                if (analyzed >= 10) break; // Ограничиваем количество
                
                const executor = new SymbolicExecutor(this.parser, funcName);
                const result = executor.execute();
                
                if (result.success) {
                    this.results.vulnerabilities.push(...result.results);
                    analyzed++;
                }
            }
        }
        
        console.log(`[Scanner] Symbolic execution analyzed ${analyzed} functions`);
    }
    
    _runStaticChecks() {
        console.log('[Scanner] Running static checks...');
        
        const checks = [
            this._checkUncheckedCalls.bind(this),
            this._checkTimestampDependence.bind(this),
            this._checkDelegatecall.bind(this),
            this._checkAccessControl.bind(this),
            this._checkFrontRunning.bind(this),
            this._checkGasIssues.bind(this)
        ];
        
        for (const check of checks) {
            try {
                const results = check();
                this.results.vulnerabilities.push(...results);
            } catch (error) {
                console.warn(`[Scanner] Check failed: ${error.message}`);
            }
        }
    }
    
    _checkUncheckedCalls() {
        const findings = [];
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (!funcInfo.body) continue;
            
            const visitor = (node) => {
                if (node.type === 'FunctionCall' && node.expression.type === 'MemberAccess') {
                    const ma = node.expression;
                    if (ma.memberName === 'call' || ma.memberName === 'send' || 
                        ma.memberName === 'transfer') {
                        
                        // Проверяем наличие проверки
                        let hasCheck = false;
                        let parent = node.parent;
                        
                        while (parent) {
                            if (parent.type === 'IfStatement' || 
                                (parent.type === 'FunctionCall' && 
                                 parent.expression && 
                                 (parent.expression.name === 'require' || 
                                  parent.expression.name === 'assert'))) {
                                hasCheck = true;
                                break;
                            }
                            parent = parent.parent;
                        }
                        
                        if (!hasCheck) {
                            findings.push({
                                type: 'UNCHECKED_CALL',
                                severity: 'MEDIUM',
                                message: `${ma.memberName} without success check`,
                                function: funcName,
                                line: this._getLineNumber(node.range[0])
                            });
                        }
                    }
                }
                
                for (const key in node) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = node[key];
                    if (Array.isArray(child)) {
                        child.forEach(visitor);
                    } else if (child && typeof child === 'object') {
                        visitor(child);
                    }
                }
            };
            
            visitor(funcInfo.body);
        }
        
        return findings;
    }
    
    _checkTimestampDependence() {
        const findings = [];
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (!funcInfo.body) continue;
            
            const visitor = (node) => {
                if (node.type === 'MemberAccess' && 
                    node.expression && node.expression.name === 'block' && 
                    node.memberName === 'timestamp') {
                    
                    const context = this.parser._getSource(node);
                    
                    // Пропускаем безопасные использования
                    if (context.toLowerCase().includes('deadline')) {
                        return;
                    }
                    
                    // Проверяем использование для рандома
                    let parent = node.parent;
                    while (parent) {
                        if (parent.type === 'BinaryOperation' && parent.operator === '%') {
                            findings.push({
                                type: 'TIMESTAMP_DEPENDENCE',
                                severity: 'MEDIUM',
                                message: 'Using block.timestamp for randomness',
                                function: funcName,
                                line: this._getLineNumber(node.range[0])
                            });
                            return;
                        }
                        parent = parent.parent;
                    }
                    
                    // Проверяем маленькие временные окна
                    if (/(block\.timestamp\s*[+-]\s*[1-5])/i.test(context)) {
                        findings.push({
                            type: 'TIMESTAMP_DEPENDENCE',
                            severity: 'MEDIUM',
                            message: 'Small time window (< 5 seconds)',
                            function: funcName,
                            line: this._getLineNumber(node.range[0])
                        });
                    }
                } else if (node.type === 'Identifier' && node.name === 'now') {
                    findings.push({
                        type: 'TIMESTAMP_DEPENDENCE',
                        severity: 'LOW',
                        message: "Using deprecated 'now' keyword",
                        function: funcName,
                        line: this._getLineNumber(node.range[0])
                    });
                }
                
                for (const key in node) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = node[key];
                    if (Array.isArray(child)) {
                        child.forEach(visitor);
                    } else if (child && typeof child === 'object') {
                        visitor(child);
                    }
                }
            };
            
            visitor(funcInfo.body);
        }
        
        return findings;
    }
    
    _checkDelegatecall() {
        const findings = [];
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (!funcInfo.body) continue;
            
            const visitor = (node) => {
                if (node.type === 'MemberAccess' && node.memberName === 'delegatecall') {
                    // Проверяем user-controlled data
                    const context = this.parser._getSource(node);
                    if (context.includes('msg.data')) {
                        findings.push({
                            type: 'DELEGATECALL',
                            severity: 'HIGH',
                            message: 'User-controlled delegatecall with msg.data',
                            function: funcName,
                            line: this._getLineNumber(node.range[0])
                        });
                    }
                    
                    // Проверяем контроль доступа
                    const hasControl = this._hasAccessControl(funcInfo);
                    if (!hasControl) {
                        findings.push({
                            type: 'DELEGATECALL',
                            severity: 'HIGH',
                            message: 'Delegatecall without access control',
                            function: funcName,
                            line: this._getLineNumber(node.range[0])
                        });
                    }
                }
                
                for (const key in node) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = node[key];
                    if (Array.isArray(child)) {
                        child.forEach(visitor);
                    } else if (child && typeof child === 'object') {
                        visitor(child);
                    }
                }
            };
            
            visitor(funcInfo.body);
        }
        
        return findings;
    }
    
    _checkAccessControl() {
        const findings = [];
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            const lowerName = funcName.toLowerCase();
            
            // Критические функции
            const isCritical = funcName.includes('transferOwnership') ||
                              funcName.includes('mint') ||
                              funcName.includes('burn') ||
                              funcName.includes('withdraw') ||
                              funcName.includes('set') ||
                              lowerName.includes('admin');
            
            if (isCritical) {
                const hasControl = this._hasAccessControl(funcInfo);
                if (!hasControl) {
                    findings.push({
                        type: 'ACCESS_CONTROL',
                        severity: 'HIGH',
                        message: 'Critical function without access control',
                        function: funcName,
                        line: this._getLineNumber(funcInfo.astNode.range[0])
                    });
                }
            }
        }
        
        return findings;
    }
    
    _checkFrontRunning() {
        const findings = [];
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            const lowerName = funcName.toLowerCase();
            
            // Функции подверженные front-running
            const isSwap = lowerName.includes('swap') || lowerName.includes('exchange');
            const isLiquidity = lowerName.includes('liquidity') || lowerName.includes('add') || lowerName.includes('remove');
            const isMint = lowerName.includes('mint') || lowerName.includes('claim');
            
            if (isSwap || isLiquidity || isMint) {
                let hasSlippage = false;
                let hasDeadline = false;
                let hasLimits = false;
                
                // Анализируем параметры
                if (funcInfo.parameters && funcInfo.parameters.parameters) {
                    for (const param of funcInfo.parameters.parameters) {
                        const paramName = (param.name || '').toLowerCase();
                        if (paramName.includes('min') || paramName.includes('max') || 
                            paramName.includes('slippage')) {
                            hasSlippage = true;
                        }
                        if (paramName.includes('deadline')) {
                            hasDeadline = true;
                        }
                        if (paramName.includes('limit') || paramName.includes('cap') || 
                            paramName.includes('max')) {
                            hasLimits = true;
                        }
                    }
                }
                
                // Анализируем тело
                if (funcInfo.body) {
                    const bodyText = this.parser._getSource(funcInfo.body).toLowerCase();
                    if (bodyText.includes('min') || bodyText.includes('max') || 
                        bodyText.includes('slippage')) {
                        hasSlippage = true;
                    }
                    if (bodyText.includes('deadline') || 
                        (bodyText.includes('block.timestamp') && bodyText.includes('require'))) {
                        hasDeadline = true;
                    }
                    if (bodyText.includes('limit') || bodyText.includes('cap') || 
                        bodyText.includes('only')) {
                        hasLimits = true;
                    }
                }
                
                if (isSwap && !hasSlippage) {
                    findings.push({
                        type: 'FRONT_RUNNING',
                        severity: 'MEDIUM',
                        message: 'Swap function lacks slippage protection',
                        function: funcName,
                        line: this._getLineNumber(funcInfo.astNode.range[0])
                    });
                }
                
                if ((isSwap || isLiquidity) && !hasDeadline) {
                    findings.push({
                        type: 'FRONT_RUNNING',
                        severity: 'MEDIUM',
                        message: 'Function lacks deadline protection',
                        function: funcName,
                        line: this._getLineNumber(funcInfo.astNode.range[0])
                    });
                }
                
                if (isMint && !hasLimits) {
                    findings.push({
                        type: 'FRONT_RUNNING',
                        severity: 'MEDIUM',
                        message: 'Mint function lacks anti-sniping protection',
                        function: funcName,
                        line: this._getLineNumber(funcInfo.astNode.range[0])
                    });
                }
            }
        }
        
        return findings;
    }
    
    _checkGasIssues() {
        const findings = [];
        
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (funcInfo.hasLoops) {
                // Проверяем unbounded loops
                findings.push({
                    type: 'GAS_ISSUE',
                    severity: 'MEDIUM',
                    message: 'Function contains loops - potential gas issue',
                    function: funcName,
                    line: this._getLineNumber(funcInfo.astNode.range[0])
                });
            }
            
            // Проверяем storage vs memory
            if (funcInfo.storageAccess) {
                const reads = funcInfo.storageAccess.reads.length;
                const writes = funcInfo.storageAccess.writes.length;
                
                if (reads + writes > 10) {
                    findings.push({
                        type: 'GAS_ISSUE',
                        severity: 'LOW',
                        message: `High storage access (${reads} reads, ${writes} writes)`,
                        function: funcName,
                        line: this._getLineNumber(funcInfo.astNode.range[0])
                    });
                }
            }
        }
        
        return findings;
    }
    
    _runTaintAnalysis() {
        console.log('[Scanner] Running taint analysis...');
        
        // Простой taint tracking через AST
        for (const [funcName, funcInfo] of this.parser.functions) {
            if (!funcInfo.body) continue;
            
            const visitor = (node) => {
                // Источники taint
                if (node.type === 'MemberAccess') {
                    if (node.expression && 
                        (node.expression.name === 'msg' || node.expression.name === 'tx') &&
                        (node.memberName === 'sender' || node.memberName === 'value' || 
                         node.memberName === 'data' || node.memberName === 'origin')) {
                        
                        const taintSource = `${node.expression.name}.${node.memberName}`;
                        // Помечаем переменную как заражённую
                        this._markTaintedInScope(node, taintSource);
                    }
                }
                
                // Sinks
                if (node.type === 'FunctionCall') {
                    if (node.expression.type === 'MemberAccess') {
                        const ma = node.expression;
                        if (ma.memberName === 'call' || ma.memberName === 'delegatecall' || 
                            ma.memberName === 'staticcall') {
                            
                            // Проверяем заражённые аргументы
                            this._checkTaintedArguments(node, funcName);
                        }
                    }
                }
                
                for (const key in node) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = node[key];
                    if (Array.isArray(child)) {
                        child.forEach(visitor);
                    } else if (child && typeof child === 'object') {
                        visitor(child);
                    }
                }
            };
            
            visitor(funcInfo.body);
        }
    }
    
    _markTaintedInScope(node, source) {
        // Находим родительский блок и помечаем переменные
        let current = node.parent;
        while (current && current.type !== 'Block' && current.type !== 'FunctionDefinition') {
            current = current.parent;
        }
        
        if (current) {
            // Помечаем все идентификаторы в этом блоке
            const markVisitor = (n) => {
                if (n.type === 'Identifier' && n.name) {
                    this.parser.taintTracker.markTainted(n.name, source);
                }
                for (const key in n) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = n[key];
                    if (Array.isArray(child)) {
                        child.forEach(markVisitor);
                    } else if (child && typeof child === 'object') {
                        markVisitor(child);
                    }
                }
            };
            
            markVisitor(current);
        }
    }
    
    _checkTaintedArguments(callNode, funcName) {
        if (!callNode.arguments) return;
        
        for (const arg of callNode.arguments) {
            const argText = this.parser._getSource(arg).toLowerCase();
            // Проверяем, содержит ли аргумент заражённые переменные
            for (const [varName, taintInfo] of this.parser.taintTracker.taintedVars) {
                if (argText.includes(varName)) {
                    this.results.vulnerabilities.push({
                        type: 'TAINTED_CALL',
                        severity: 'HIGH',
                        message: `Tainted data '${varName}' used in external call`,
                        function: funcName,
                        source: taintInfo.source,
                        line: this._getLineNumber(callNode.range[0])
                    });
                }
            }
        }
    }
    
    _runPatternMatching() {
        const patterns = {
            // ERC20 approve front-running
            'ERC20_APPROVE_FRONT_RUN': /approve\(.*,\s*0\)/g,
            
            // Transfer without return check
            'TRANSFER_NO_CHECK': /\.transfer\([^)]+\)(?!\s*\{)/g,
            
            // Send without check
            'SEND_NO_CHECK': /\.send\([^)]+\)(?!\s*\{)/g,
            
            // Call with gas but no value
            'CALL_WITH_GAS': /\.call\{gas:[^}]+\}\(/g,
            
            // Selfdestruct
            'SELFDESTRUCT': /selfdestruct\(/g,
            
            // Suicide (deprecated)
            'SUICIDE': /suicide\(/g,
            
            // Blockhash usage
            'BLOCKHASH': /blockhash\(/g,
            
            // Assembly usage
            'ASSEMBLY': /\basembly\b/g,
            
            // Inline assembly
            'INLINE_ASSEMBLY': /\{[\s\S]*?assembly[\s\S]*?\}/g
        };
        
        for (const [patternName, pattern] of Object.entries(patterns)) {
            const matches = this.sourceCode.match(pattern);
            if (matches) {
                matches.forEach(match => {
                    const position = this.sourceCode.indexOf(match);
                    this.results.warnings.push({
                        type: patternName,
                        severity: 'MEDIUM',
                        message: `Pattern '${patternName}' found`,
                        pattern: match,
                        line: this._getLineNumber(position)
                    });
                });
            }
        }
    }
    
    _hasAccessControl(funcInfo) {
        // Проверяем модификаторы доступа
        if (funcInfo.modifiers && funcInfo.modifiers.length > 0) {
            const accessModifiers = ['onlyowner', 'onlyadmin', 'onlyrole', 
                                    'auth', 'authenticated', 'restricted'];
            
            for (const mod of funcInfo.modifiers) {
                const modName = (mod.name || '').toLowerCase();
                if (accessModifiers.some(am => modName.includes(am))) {
                    return true;
                }
            }
        }
        
        // Проверяем ручные проверки в теле
        if (funcInfo.body) {
            const visitor = (node) => {
                if (node.type === 'FunctionCall' && node.expression) {
                    const funcName = node.expression.name || '';
                    if (funcName.toLowerCase() === 'require' || 
                        funcName.toLowerCase() === 'assert') {
                        
                        const args = this.parser._getSource(node).toLowerCase();
                        if (args.includes('msg.sender') && 
                            (args.includes('owner') || args.includes('admin'))) {
                            return true;
                        }
                    }
                }
                
                for (const key in node) {
                    if (key === 'parent' || key === 'range' || key === 'loc') continue;
                    const child = node[key];
                    if (Array.isArray(child)) {
                        for (const item of child) {
                            const result = visitor(item);
                            if (result) return true;
                        }
                    } else if (child && typeof child === 'object') {
                        const result = visitor(child);
                        if (result) return true;
                    }
                }
                
                return false;
            };
            
            return visitor(funcInfo.body);
        }
        
        return false;
    }
    
    _getLineNumber(pos) {
        const code = this.sourceCode.substring(0, pos);
        return code.split('\n').length;
    }
}

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

// ========== ИНТЕРФЕЙС ДЛЯ КОМАНДНОЙ СТРОКИ ==========
if (require.main === module) {
    const fs = require('fs');
    const path = require('path');
    const { Command } = require('commander');
    
    const program = new Command();
    
    program
        .name('solidity-scanner')
        .description('Industrial-grade Solidity security scanner')
        .version('1.0.0')
        .option('-f, --file <path>', 'Solidity file to analyze')
        .option('-d, --dir <path>', 'Directory to analyze')
        .option('-o, --output <path>', 'Output file for results')
        .option('-j, --json', 'Output in JSON format')
        .option('-v, --verbose', 'Verbose output')
        .parse(process.argv);
    
    const options = program.opts();
    
    async function main() {
        try {
            if (options.file) {
                const sourceCode = fs.readFileSync(options.file, 'utf8');
                const scanner = new IndustrialSecurityScanner(sourceCode);
                const result = scanner.scan();
                
                if (options.json || options.output) {
                    const output = JSON.stringify(result, null, 2);
                    
                    if (options.output) {
                        fs.writeFileSync(options.output, output);
                        console.log(`Results written to ${options.output}`);
                    } else {
                        console.log(output);
                    }
                } else {
                    console.log('\n' + '='.repeat(80));
                    console.log('INDUSTRIAL SOLIDITY SECURITY SCANNER');
                    console.log('='.repeat(80));
                    
                    if (!result.success) {
                        console.error(`\n❌ Scan failed: ${result.error}`);
                        process.exit(1);
                    }
                    
                    const stats = result.results.stats;
                    console.log(`\n📊 Statistics:`);
                    console.log(`  Parse time: ${stats.parsing?.parseTime.toFixed(2)}ms`);
                    console.log(`  Total time: ${stats.totalTime.toFixed(2)}ms`);
                    console.log(`  Contracts: ${stats.parsing?.contracts || 0}`);
                    console.log(`  Functions: ${stats.functionsAnalyzed || 0}`);
                    console.log(`  Vulnerabilities: ${stats.vulnerabilitiesFound || 0}`);
                    console.log(`  Warnings: ${stats.warningsFound || 0}`);
                    
                    if (result.results.vulnerabilities.length > 0) {
                        console.log('\n🔴 VULNERABILITIES FOUND:');
                        result.results.vulnerabilities.forEach((vuln, i) => {
                            console.log(`\n${i + 1}. [${vuln.severity}] ${vuln.type}`);
                            console.log(`   Function: ${vuln.function}`);
                            console.log(`   Message: ${vuln.message}`);
                            if (vuln.line) console.log(`   Line: ${vuln.line}`);
                        });
                    }
                    
                    if (result.results.warnings.length > 0) {
                        console.log('\n🟡 WARNINGS:');
                        result.results.warnings.forEach((warning, i) => {
                            console.log(`\n${i + 1}. [${warning.severity}] ${warning.type}`);
                            console.log(`   Message: ${warning.message}`);
                            if (warning.line) console.log(`   Line: ${warning.line}`);
                        });
                    }
                    
                    if (result.results.vulnerabilities.length === 0 && 
                        result.results.warnings.length === 0) {
                        console.log('\n✅ No vulnerabilities or warnings found!');
                    }
                    
                    console.log('\n' + '='.repeat(80));
                }
                
            } else if (options.dir) {
                console.error('Directory scanning not implemented yet');
                process.exit(1);
            } else {
                // Тестовый режим
                console.log('Test mode - no file specified');
                console.log('Usage: node scanner.js -f contract.sol');
            }
            
        } catch (error) {
            console.error(`Fatal error: ${error.message}`);
            if (options.verbose) {
                console.error(error.stack);
            }
            process.exit(1);
        }
    }
    
    main();
}

// Экспорт для использования
module.exports = {
    IndustrialSecurityScanner,
    IndustrialParser,
    SymbolicExecutor,
    InterproceduralAnalyzer,
    CallGraph,
    SymbolicState,
    TaintTracker,
    parseVersionFromPragma,
    versionGe
};
