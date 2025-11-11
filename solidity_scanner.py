#!/usr/bin/env python3
# solidity_scanner.py (improved but compatible version)

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
        # Улучшенный паттерн для функций
        pattern = re.compile(r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^{]*\)\s*(?:public|private|internal|external)?\s*(?:view|pure|payable)?\s*(?:returns\s*\([^)]*\))?\s*\{', re.S)
        
        for m in pattern.finditer(src):
            sig_start = m.start()
            sig = m.group(0)  # Вся сигнатура
            brace_pos = m.end() - 1
            
            # Находим тело функции
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

# ========== УЛУЧШЕННЫЙ АНАЛИЗАТОР БЕЗОПАСНОСТИ ==========
class AdvancedSecurityChecks:
    @staticmethod
    def check_reentrancy(func):
        findings = []
        b = func['body']
        
        # Улучшенные паттерны для external calls
        call_patterns = [
            r'\.call\{[^}]*value:[^}]*\}[^)]*\)',  # .call{value: ...}()
            r'\.call\([^)]*\)',                    # .call()
            r'\.transfer\([^)]*\)',                # .transfer()
            r'\.send\([^)]*\)',                    # .send()
            r'msg\.sender\.call',                  # msg.sender.call
            r'address\([^)]*\)\.call'              # address(...).call
        ]
        
        # State change patterns
        state_patterns = [
            r'balances\[[^\]]*\]\s*=',
            r'balanceOf\[[^\]]*\]\s*=',
            r'_\w+\s*=',
            r'=\s*0\b',
            r'\-\=',
            r'\+\='
        ]
        
        # Ищем все external calls
        calls = []
        for pattern in call_patterns:
            for match in re.finditer(pattern, b, re.IGNORECASE):
                calls.append({
                    'text': match.group(),
                    'pos': match.start(),
                    'line': b[:match.start()].count('\n') + 1
                })
        
        # Ищем все state changes
        states = []
        for pattern in state_patterns:
            for match in re.finditer(pattern, b, re.IGNORECASE):
                states.append({
                    'text': match.group(),
                    'pos': match.start(),
                    'line': b[:match.start()].count('\n') + 1
                })
        
        # Анализируем порядок: call до state change = реентранси
        for call in calls:
            for state in states:
                if call['pos'] < state['pos']:
                    findings.append(f"REENTRANCY: External call at line {call['line']} before state update at line {state['line']} - {call['text']} → {state['text']}")
        
        # Проверка на calls в циклах
        if calls and re.search(r'(for|while)\s*\([^)]*\)\s*\{[^}]*\.call', b, re.DOTALL | re.IGNORECASE):
            findings.append("REENTRANCY: External calls inside loops - potential DoS risk")
            
        return findings

    @staticmethod
    def check_overflow(src, func, pragma):
        findings = []
        b = func['body']
        
        # Проверка версии Solidity
        if pragma and any(ver in pragma for ver in ['^0.7', '0.6', '0.5', '0.4']):
            findings.append("OVERFLOW: Using older Solidity version - no built-in overflow protection")
        
        # Поиск арифметических операций без проверок
        arithmetic_patterns = [
            (r'(\w+)\s*\+\s*(\w+)', 'addition'),
            (r'(\w+)\s*\-\s*(\w+)', 'subtraction'),
            (r'(\w+)\s*\*\s*(\w+)', 'multiplication'),
            (r'(\w+)\s*\/\s*(\w+)', 'division'),
            (r'\+\+', 'increment'),
            (r'\-\-', 'decrement')
        ]
        
        for pattern, op_type in arithmetic_patterns:
            for match in re.finditer(pattern, b):
                # Проверяем контекст на наличие проверок
                context_start = max(0, match.start() - 100)
                context_end = min(len(b), match.end() + 100)
                context = b[context_start:context_end]
                
                # Если нет проверок в контексте
                if not any(check in context for check in ['require', 'assert', 'if', 'SafeMath']):
                    findings.append(f"OVERFLOW: Unchecked {op_type} operation: {match.group()}")
        
        # Unchecked блоки
        if 'unchecked' in b:
            findings.append("OVERFLOW: 'unchecked' block found - arithmetic operations may overflow")
            
        # Маленькие типы
        if re.search(r'\buint(8|16|32|40|48|56|64)\b', func['signature'] + b):
            findings.append("OVERFLOW: Using small integer types - risk of overflow/underflow")
            
        return findings

    @staticmethod
    def check_unchecked_call(func):
        findings = []
        b = func['body']
        
        # Проверка ERC20 transfer без проверки возврата
        if re.search(r'\.transfer\(', b) and not re.search(r'require\(.*\.transfer\(', b):
            findings.append("UNCHECKED_CALL: ERC20 transfer() without return value check")
        
        # Low-level calls без проверки success
        call_matches = list(re.finditer(r'\.call\{[^}]*\}[^)]*\)', b))
        for match in call_matches:
            call_code = match.group()
            if 'bool' not in call_code and 'require' not in call_code:
                findings.append(f"UNCHECKED_CALL: Low-level call without success check: {call_code}")
        
        # Send без проверки
        if re.search(r'\.send\(', b) and not re.search(r'require\(.*\.send\(', b):
            findings.append("UNCHECKED_CALL: .send() without return value check")
            
        return findings

    @staticmethod
    def check_access_control(func):
        findings = []
        b = func['body']
        sig = func['signature'].lower()
        
        # Критические операции
        critical_ops = [
            (r'selfdestruct\(', 'selfdestruct'),
            (r'\.delegatecall\(', 'delegatecall'),
            (r'\.call\{[^}]*value:[^}]*\}', 'value_transfer'),
            (r'\.mint\(', 'mint_tokens'),
            (r'\.burn\(', 'burn_tokens')
        ]
        
        for pattern, op_name in critical_ops:
            if re.search(pattern, b, re.IGNORECASE):
                # Проверяем наличие контроля доступа
                has_control = any(mod in sig for mod in ['onlyowner', 'onlyowner', 'modifier']) or 'require(msg.sender' in b
                
                if not has_control:
                    findings.append(f"ACCESS_CONTROL: Critical operation '{op_name}' without access control")
                    
        return findings

# ========== СОВМЕСТИМЫЙ ИНТЕРФЕЙС ==========
def analyze_source(src_text):
    """
    Главная функция (совместима с оригинальной версией)
    """
    parser = EnhancedParser()
    checker = AdvancedSecurityChecks()
    
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
        global_msgs.append("No issues found by heuristics for the scanned functions. Это НЕ гарантия безопасности — рекомендуется Slither/Mythril/формальный аудит.")
    
    return {
        'pragma': pragma,
        'functions': report,
        'global_msgs': global_msgs
    }

# ========== ТЕСТИРОВАНИЕ ==========
if __name__ == '__main__':
    # Тестовый код с уязвимостями
    test_code = """
    pragma solidity ^0.7.0;
    
    contract VulnerableBank {
        mapping(address => uint) public balances;
        
        function withdraw() public {
            // Реентранси уязвимость
            (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
            require(success);
            balances[msg.sender] = 0; // State change AFTER call
        }
        
        function transfer(address to, uint amount) public {
            // Переполнение
            balances[msg.sender] -= amount;
            balances[to] += amount; // No overflow check
        }
        
        function unsafeDecrement(address user, uint value) public {
            unchecked {
                balances[user] -= value; // Unchecked underflow
            }
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
