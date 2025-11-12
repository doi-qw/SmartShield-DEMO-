#!/usr/bin/env python3
# solidity_scanner.py (with front-running and timestamp attacks)

import re
import json
from typing import List, Dict, Any

# ========== УЛУЧШЕННЫЙ ПАРСЕР ==========
class EnhancedParser:
    @staticmethod
    def find_pragma(content):
        m = re.search(r'pragma\s+solidity\s+([^;]+);', content)
        return m.group(1).strip() if m else None

    @staticmethod
    def extract_functions(src):
        funcs = []
        pattern = re.compile(r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^{]*\)\s*(?:public|private|internal|external)?\s*(?:view|pure|payable)?\s*(?:returns\s*\([^)]*\))?\s*\{', re.S)
        
        for m in pattern.finditer(src):
            sig_start = m.start()
            sig = m.group(0)
            brace_pos = m.end() - 1
            
            depth = 0
            i = brace_pos
            while i < len(src):
                if src[i] == '{':
                    depth += 1
                elif src[i] == '}':
                    depth -= 1
                    if depth == 0:
                        body = src[brace_pos+1:i]
                        func_name = m.group(1)
                        funcs.append({
                            'name': func_name,
                            'signature': sig.strip(),
                            'body': body,
                            'start': sig_start,
                            'end': i+1
                        })
                        break
                i += 1
        return funcs

# ========== УМНЫЙ АНАЛИЗАТОР С ДОПОЛНИТЕЛЬНЫМИ ПРОВЕРКАМИ ==========
class SmartSecurityChecks:
    
    @staticmethod
    def is_library_or_view_function(func):
        """Проверяем, является ли функция view/pure или в библиотеке"""
        sig_lower = func['signature'].lower()
        return 'view' in sig_lower or 'pure' in sig_lower
    
    @staticmethod
    def has_reentrancy_guard(body):
        """Проверяем наличие защиты от реентранси"""
        reentrancy_indicators = [
            'nonReentrant',
            'reentrancyGuard',
            'lock\n',
            'locked.*=.*true',
            'Mutex',
            'NoReentrancy'
        ]
        return any(indicator in body for indicator in reentrancy_indicators)
    
    @staticmethod
    def is_safe_arithmetic_context(context):
        """Проверяем безопасный контекст для арифметики"""
        safe_indicators = [
            'require(',
            'assert(',
            'if (',
            'SafeMath',
            'safeAdd',
            'safesub',
            'unchecked',
        ]
        return any(indicator in context for indicator in safe_indicators)
    
    @staticmethod
    def is_assembly_safe_operation(operation, context):
        """Проверяем безопасность ассемблерных операций"""
        safe_assembly_patterns = [
            r'mload\(',
            r'mstore\(',
            r'add\(.*32\)',
            r'and\(.*0x',
            r'shl\(',
            r'shr\('
        ]
        
        for pattern in safe_assembly_patterns:
            if re.search(pattern, context):
                return True
        return False

    @staticmethod
    def check_reentrancy(func):
        findings = []
        b = func['body']
        
        if SmartSecurityChecks.is_library_or_view_function(func):
            return findings
            
        if SmartSecurityChecks.has_reentrancy_guard(b):
            return findings
        
        call_patterns = [
            r'\.call\{[^}]*value:\s*[^}]*\}[^)]*\)',
            r'\.transfer\([^)]*\)',
            r'\.send\([^)]*\)',
        ]
        
        state_patterns = [
            r'balances\[[^\]]*\]\s*=\s*0',
            r'balanceOf\[[^\]]*\]\s*=\s*0',
            r'_balances\[[^\]]*\]\s*=\s*0',
            r'totalSupply\s*\-=',
        ]
        
        calls = []
        for pattern in call_patterns:
            for match in re.finditer(pattern, b, re.IGNORECASE):
                if '.call{' in match.group() and 'value:' not in match.group():
                    continue
                calls.append({
                    'text': match.group(),
                    'pos': match.start(),
                    'line': b[:match.start()].count('\n') + 1
                })
        
        states = []
        for pattern in state_patterns:
            for match in re.finditer(pattern, b, re.IGNORECASE):
                states.append({
                    'text': match.group(),
                    'pos': match.start(),
                    'line': b[:match.start()].count('\n') + 1
                })
        
        for call in calls:
            for state in states:
                if call['pos'] < state['pos']:
                    between_code = b[call['pos']:state['pos']]
                    if not re.search(r'require\(|assert\(|revert\(', between_code):
                        findings.append(f"REENTRANCY: External call at line {call['line']} before state update at line {state['line']}")

        return findings

    @staticmethod
    def check_overflow(src, func, pragma):
        findings = []
        b = func['body']
        
        is_view_pure = SmartSecurityChecks.is_library_or_view_function(func)
        
        if pragma and any(ver in pragma for ver in ['0.6', '0.5', '0.4']):
            findings.append("OVERFLOW: Using older Solidity version - no built-in overflow protection")
        
        arithmetic_patterns = [
            (r'(\w+)\s*\+\s*(\w+)', 'addition'),
            (r'(\w+)\s*\-\s*(\w+)', 'subtraction'),
            (r'(\w+)\s*\*\s*(\w+)', 'multiplication'),
        ]
        
        for pattern, op_type in arithmetic_patterns:
            for match in re.finditer(pattern, b):
                context_start = max(0, match.start() - 150)
                context_end = min(len(b), match.end() + 150)
                context = b[context_start:context_end]
                
                if SmartSecurityChecks.is_safe_arithmetic_context(context):
                    continue
                    
                if 'assembly' in context and SmartSecurityChecks.is_assembly_safe_operation(match.group(), context):
                    continue
                
                if re.search(r'\b\d+\s*[\+\-\*]\s*\d+\b', match.group()):
                    continue
                    
                findings.append(f"OVERFLOW: Unchecked {op_type} operation: {match.group()}")
        
        unchecked_blocks = list(re.finditer(r'unchecked\s*\{([^}]*)\}', b, re.DOTALL))
        for match in unchecked_blocks:
            unchecked_body = match.group(1)
            if re.search(r'[\+\-\*\/]\=|[\+\-\*\/]\s|\+\+|\-\-', unchecked_body):
                findings.append("OVERFLOW: 'unchecked' block with arithmetic operations")
        
        small_types_match = re.search(r'\buint(8|16|32)\b', func['signature'] + b)
        if small_types_match and re.search(r'[\+\-\*\/]', b):
            findings.append("OVERFLOW: Small integer types used in arithmetic operations")
            
        return findings

    @staticmethod
    def check_unchecked_call(func):
        findings = []
        b = func['body']
        
        if not SmartSecurityChecks.is_library_or_view_function(func):
            transfer_matches = list(re.finditer(r'\.transfer\([^)]*\)', b))
            for match in transfer_matches:
                context_start = max(0, match.start() - 50)
                context_end = min(len(b), match.end() + 50)
                context = b[context_start:context_end]
                
                if not re.search(r'require\(|assert\(|if\s*\(.*success', context):
                    findings.append("UNCHECKED_CALL: ERC20 transfer() without return value check")
        
        call_matches = list(re.finditer(r'\.call\{[^}]*\}[^)]*\)', b))
        for match in call_matches:
            call_code = match.group()
            if 'value:' not in call_code:
                continue
                
            context_start = max(0, match.start() - 100)
            context_end = min(len(b), match.end() + 100)
            context = b[context_start:context_end]
            
            if not re.search(r'(require|assert|if).*success', context, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: Value transfer call without success check")
        
        return findings

    @staticmethod
    def check_access_control(func):
        findings = []
        b = func['body']
        sig = func['signature'].lower()
        
        critical_ops = [
            (r'selfdestruct\(', 'selfdestruct'),
            (r'\.delegatecall\(', 'delegatecall'),
        ]
        
        for pattern, op_name in critical_ops:
            if re.search(pattern, b, re.IGNORECASE):
                has_control = (
                    any(mod in sig for mod in ['onlyowner', 'onlyadmin', 'onlyrole', 'modifier']) or 
                    re.search(r'require\(.*msg\.sender.*==.*owner', b) or
                    re.search(r'require\(.*hasRole\(', b)
                )
                
                if not has_control:
                    findings.append(f"ACCESS_CONTROL: Critical operation '{op_name}' without access control")
                    
        return findings

    @staticmethod
    def check_front_running(func):
        """Проверка уязвимостей фронт-раннинга"""
        findings = []
        b = func['body']
        
        # Паттерны указывающие на возможный фронт-раннинг
        front_running_patterns = [
            # AMM операции без slippage protection
            (r'addLiquidity\([^)]*\)', 'addLiquidity without slippage protection'),
            (r'removeLiquidity\([^)]*\)', 'removeLiquidity without slippage protection'),
            (r'swapExactTokensForTokens\([^)]*\)', 'swap without slippage protection'),
            (r'swapTokensForExactTokens\([^)]*\)', 'swap without slippage protection'),
            
            # Ценовые операции без deadline
            (r'getAmountsOut\([^)]*\)', 'price calculation without deadline protection'),
            (r'getAmountsIn\([^)]*\)', 'price calculation without deadline protection'),
            
            # Minting без ограничений
            (r'\.mint\([^)]*\)', 'minting without anti-sniping protection'),
        ]
        
        for pattern, description in front_running_patterns:
            if re.search(pattern, b, re.IGNORECASE):
                # Проверяем наличие защиты от фронт-раннинга
                has_protection = (
                    re.search(r'deadline\s*=', b) or
                    re.search(r'slippage', b, re.IGNORECASE) or
                    re.search(r'amountOutMin\s*=', b) or
                    re.search(r'amountInMax\s*=', b) or
                    re.search(r'block\.timestamp', b)  # использование timestamp для deadline
                )
                
                if not has_protection:
                    findings.append(f"FRONT_RUNNING: {description}")
        
        # Проверка на sandwich attacks в price calculations
        if re.search(r'getReserves\(\)|getAmounts', b):
            # Если есть расчет цен но нет минимальных/максимальных ограничений
            if not re.search(r'(amountOutMin|amountInMax|minAmount|maxAmount)\s*=', b):
                findings.append("FRONT_RUNNING: Price calculation without min/max amount protection")
        
        return findings

    @staticmethod
    def check_timestamp_dependence(func):
        """Проверка уязвимостей зависимости от timestamp"""
        findings = []
        b = func['body']
        
        # Поиск использования block.timestamp в критических операциях
        timestamp_uses = list(re.finditer(r'block\.timestamp|block\.timestamp|now', b, re.IGNORECASE))
        
        for match in timestamp_uses:
            context_start = max(0, match.start() - 100)
            context_end = min(len(b), match.end() + 100)
            context = b[context_start:context_end]
            
            # Критические контексты где timestamp опасен
            critical_contexts = [
                # Рандом генерация
                (r'=\s*.*block\.timestamp.*%', 'timestamp used for randomness'),
                # Условия выплат/наград
                (r'if.*block\.timestamp', 'timestamp in conditional logic'),
                # Лотереи/аукционы
                (r'winner.*block\.timestamp', 'timestamp for winner selection'),
                # Временные ограничения с малыми окнами
                (r'block\.timestamp.*[+-].*[1-5]', 'small time window manipulation risk'),
            ]
            
            for pattern, description in critical_contexts:
                if re.search(pattern, context, re.IGNORECASE):
                    findings.append(f"TIMESTAMP_DEPENDENCE: {description}")
                    
            # Проверка на использование timestamp для генерации случайных чисел
            if re.search(r'keccak256.*block\.timestamp|uint.*=.*block\.timestamp.*%', context):
                findings.append("TIMESTAMP_DEPENDENCE: Using timestamp for randomness - miners can manipulate")
        
        # Проверка на временные ограничения которые могут быть обмануты
        time_patterns = [
            (r'require\(.*block\.timestamp.*>.*\d+', 'timestamp requirement without buffer'),
            (r'require\(.*block\.timestamp.*<.*\d+', 'timestamp requirement without buffer'),
        ]
        
        for pattern, description in time_patterns:
            if re.search(pattern, b):
                findings.append(f"TIMESTAMP_DEPENDENCE: {description}")
        
        return findings

    @staticmethod
    def check_delegatecall_vulnerabilities(func):
        """Проверка уязвимостей delegatecall"""
        findings = []
        b = func['body']
        
        # Поиск delegatecall вызовов
        delegatecall_matches = list(re.finditer(r'\.delegatecall\([^)]*\)', b, re.IGNORECASE))
        
        for match in delegatecall_matches:
            context_start = max(0, match.start() - 150)
            context_end = min(len(b), match.end() + 150)
            context = b[context_start:context_end]
            
            # Проверяем опасные паттерны
            vulnerabilities = [
                # Delegatecall к пользовательскому адресу
                (r'\.delegatecall.*msg\.data', 'user-controlled delegatecall - PARITY WALLET HACK'),
                # Delegatecall без проверки адреса
                (r'\.delegatecall.*\(\)', 'delegatecall without address validation'),
                # Delegatecall в fallback функциях
                (r'fallback.*delegatecall', 'delegatecall in fallback function'),
            ]
            
            for pattern, description in vulnerabilities:
                if re.search(pattern, context, re.IGNORECASE):
                    findings.append(f"DELEGATECALL: {description}")
            
            # Проверяем что адрес для delegatecall проверен
            if not re.search(r'require\(.*address.*==.*0x', context):
                findings.append("DELEGATECALL: Delegatecall to potentially untrusted address")
        
        return findings

# ========== СОВМЕСТИМЫЙ ИНТЕРФЕЙС ==========
def analyze_source(src_text):
    """
    Главная функция (совместима с оригинальной версией)
    """
    parser = EnhancedParser()
    checker = SmartSecurityChecks()
    
    pragma = parser.find_pragma(src_text)
    funcs = parser.extract_functions(src_text)
    report = []
    
    for f in funcs:
        f_findings = []
        
        # Запускаем все проверки
        f_findings.extend(checker.check_reentrancy(f))
        f_findings.extend(checker.check_overflow(src_text, f, pragma))
        f_findings.extend(checker.check_unchecked_call(f))
        f_findings.extend(checker.check_access_control(f))
        f_findings.extend(checker.check_front_running(f))           # НОВАЯ ПРОВЕРКА
        f_findings.extend(checker.check_timestamp_dependence(f))    # НОВАЯ ПРОВЕРКА
        f_findings.extend(checker.check_delegatecall_vulnerabilities(f))  # НОВАЯ ПРОВЕРКА
        
        if f_findings:
            snippet = f['body'][:1000].strip()
            report.append({
                'function': f['name'],
                'signature': f['signature'],
                'issues': f_findings,
                'snippet': snippet
            })
    
    global_msgs = []
    if not report:
        global_msgs.append("No critical issues found. Рекомендуется дополнительная проверка с помощью Slither/Mythril.")
    
    return {
        'pragma': pragma,
        'functions': report,
        'global_msgs': global_msgs
    }

# ========== ТЕСТИРОВАНИЕ ==========
if __name__ == '__main__':
    # Тестовый код с новыми уязвимостями
    test_code = """
    pragma solidity ^0.8.4;
    
    contract VulnerableDEX {
        mapping(address => uint) public balances;
        
        // Фронт-раннинг уязвимость - нет slippage protection
        function swapTokens(address tokenIn, uint amountIn) public {
            // ... логика свопа
            // НЕТ amountOutMin или deadline - УЯЗВИМОСТЬ!
        }
        
        // Timestamp уязвимость - использование для рандома
        function luckyDraw() public {
            uint random = uint(keccak256(abi.encodePacked(block.timestamp))) % 100;
            if (random == 42) {
                // выигрыш - УЯЗВИМОСТЬ!
            }
        }
        
        // Delegatecall уязвимость - Parity Wallet hack style
        function execute(address target, bytes memory data) public {
            target.delegatecall(data); // УЯЗВИМОСТЬ - пользовательский адрес!
        }
        
        // Безопасная функция с защитой
        function safeSwap(address tokenIn, uint amountIn, uint amountOutMin) public {
            require(amountOutMin > 0, "Slippage protection");
            // ... безопасная логика
        }
    }
    """
    
    result = analyze_source(test_code)
    print("=== РЕЗУЛЬТАТЫ АНАЛИЗА ===")
    print(f"Pragma: {result['pragma']}")
    print(f"Найдено функций с проблемами: {len(result['functions'])}")
    
    for func in result['functions']:
        print(f"\n--- Функция: {func['function']} ---")
        print(f"Сигнатура: {func['signature']}")
        print("Проблемы:")
        for issue in func['issues']:
            print(f"  - {issue}")
    
    for msg in result['global_msgs']:
        print(f"\nℹ️  {msg}")
