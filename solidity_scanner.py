#!/usr/bin/env python3
# solidity_scanner_pro.py
# УЛУЧШЕННЫЙ сканер для Solidity - теперь с настоящим анализом!

import re
import json
from typing import List, Dict, Any, Tuple
import warnings

# Конфигурация
class Config:
    MAX_BODY_LENGTH = 5000
    MIN_CONFIDENCE = 0.3

class SolidityParser:
    """Улучшенный парсер Solidity"""
    
    @staticmethod
    def find_pragma(content: str) -> str:
        """Находит pragma solidity"""
        patterns = [
            r'pragma\s+solidity\s+([^;]+);',
            r'pragma\s+solidity\s+(\^?\d+\.\d+\.\d+);'
        ]
        for pattern in patterns:
            m = re.search(pattern, content)
            if m:
                return m.group(1).strip()
        return "unknown"
    
    @staticmethod
    def extract_contracts(content: str) -> List[Dict]:
        """Извлекает контракты и их содержимое"""
        contracts = []
        pattern = r'(contract|library|interface)\s+(\w+)[^{]*\{'
        
        for match in re.finditer(pattern, content):
            contract_type = match.group(1)
            contract_name = match.group(2)
            start_pos = match.start()
            
            # Находим границы контракта
            brace_count = 0
            i = match.end() - 1
            while i < len(content):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        contract_body = content[match.end()-1:i+1]
                        contracts.append({
                            'type': contract_type,
                            'name': contract_name,
                            'body': contract_body,
                            'full_content': content[start_pos:i+1]
                        })
                        break
                i += 1
        return contracts
    
    @staticmethod
    def extract_functions(content: str) -> List[Dict]:
        """Улучшенное извлечение функций с поддержкой модификаторов"""
        functions = []
        
        # Более умный паттерн для функций
        pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^{]*\)\s*(?:public|private|internal|external)?\s*(?:view|pure|payable)?\s*(?:returns\s*\([^)]*\))?\s*\{'
        
        for match in re.finditer(pattern, content, re.DOTALL):
            func_name = match.group(1)
            start_pos = match.start()
            brace_pos = match.end() - 1
            
            # Находим тело функции
            brace_count = 1
            i = brace_pos + 1
            while i < len(content) and brace_count > 0:
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                i += 1
            
            if brace_count == 0:
                body = content[brace_pos+1:i-1]
                functions.append({
                    'name': func_name,
                    'signature': content[start_pos:brace_pos+1].strip(),
                    'body': body,
                    'full_code': content[start_pos:i],
                    'start': start_pos,
                    'end': i
                })
        
        return functions
    
    @staticmethod
    def extract_state_variables(content: str) -> List[Dict]:
        """Извлекает state variables"""
        variables = []
        patterns = [
            r'(mapping|uint|address|bool|string|bytes)\s*(?:\[\s*\])?\s+(\w+)\s*;',
            r'(\w+)\s+public\s+(\w+)\s*;'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                var_type = match.group(1)
                var_name = match.group(2)
                variables.append({
                    'type': var_type,
                    'name': var_name,
                    'line': content[:match.start()].count('\n') + 1
                })
        return variables

class AdvancedSecurityAnalyzer:
    """Продвинутый анализатор безопасности"""
    
    def __init__(self):
        self.parser = SolidityParser()
    
    def analyze_reentrancy(self, function: Dict) -> List[Dict]:
        """Улучшенный анализ реентранси"""
        findings = []
        body = function['body']
        
        # Паттерны external calls
        call_patterns = [
            r'\.call\{[^}]*value:[^}]*\}[^)]*\)',
            r'\.call\([^)]*\)',
            r'\.transfer\([^)]*\)',
            r'\.send\([^)]*\)',
            r'msg\.sender\.call',
            r'address\([^)]*\)\.call'
        ]
        
        # State change patterns
        state_patterns = [
            r'balances\[[^\]]*\]\s*=',
            r'balanceOf\[[^\]]*\]\s*=',
            r'_\w+\s*=',
            r'\.transferFrom\([^)]*\)',
            r'\.approve\([^)]*\)'
        ]
        
        calls_found = []
        for pattern in call_patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                calls_found.append({
                    'type': 'external_call',
                    'match': match.group(),
                    'position': match.start(),
                    'line': body[:match.start()].count('\n') + 1
                })
        
        state_changes_found = []
        for pattern in state_patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                state_changes_found.append({
                    'type': 'state_change',
                    'match': match.group(),
                    'position': match.start(),
                    'line': body[:match.start()].count('\n') + 1
                })
        
        # Анализ порядка: call до state change?
        for call in calls_found:
            for state_change in state_changes_found:
                if call['position'] < state_change['position']:
                    # Найден потенциальный паттерн реентранси
                    findings.append({
                        'type': 'reentrancy',
                        'severity': 'HIGH',
                        'message': f"External call before state update: {call['match']} → {state_change['match']}",
                        'confidence': 0.8,
                        'line': call['line'],
                        'fix_suggestion': "Apply Checks-Effects-Interactions pattern: update state before external calls"
                    })
        
        # Проверка на call в циклах (DoS)
        if calls_found and re.search(r'(for|while)\s*\([^)]*\)\s*\{[^}]*\.call', body, re.DOTALL):
            findings.append({
                'type': 'reentrancy_dos',
                'severity': 'MEDIUM', 
                'message': "External calls inside loops - potential DoS risk",
                'confidence': 0.6,
                'line': 0,
                'fix_suggestion': "Avoid external calls in loops or use pull payment pattern"
            })
        
        return findings
    
    def analyze_overflow(self, function: Dict, pragma: str) -> List[Dict]:
        """Улучшенный анализ переполнений"""
        findings = []
        body = function['body']
        signature = function['signature']
        
        # Анализ версии pragma
        if pragma and any(ver in pragma for ver in ['^0.7', '0.6', '0.5', '0.4']):
            findings.append({
                'type': 'overflow_compiler',
                'severity': 'HIGH',
                'message': f"Using older Solidity version {pragma} - no built-in overflow protection",
                'confidence': 0.9,
                'line': 1,
                'fix_suggestion': "Upgrade to Solidity ^0.8.0 or use SafeMath library"
            })
        
        # Поиск арифметических операций
        arithmetic_ops = [
            (r'(\w+)\s*\+\s*(\w+)', 'addition'),
            (r'(\w+)\s*\-\s*(\w+)', 'subtraction'), 
            (r'(\w+)\s*\*\s*(\w+)', 'multiplication'),
            (r'(\w+)\s*\/\s*(\w+)', 'division'),
            (r'\+\+', 'increment'),
            (r'\-\-', 'decrement')
        ]
        
        for pattern, op_type in arithmetic_ops:
            for match in re.finditer(pattern, body):
                context = self._get_context(body, match.start(), 100)
                
                # Проверяем, есть ли проверки вокруг
                has_checks = self._has_safety_checks(context)
                
                if not has_checks:
                    findings.append({
                        'type': f'arithmetic_{op_type}',
                        'severity': 'MEDIUM',
                        'message': f"Unchecked {op_type} operation: {match.group()}",
                        'confidence': 0.7,
                        'line': body[:match.start()].count('\n') + 1,
                        'fix_suggestion': "Add require() checks or use SafeMath for arithmetic operations"
                    })
        
        # Поиск unchecked блоков
        unchecked_blocks = list(re.finditer(r'unchecked\s*\{[^}]*\}', body, re.DOTALL))
        for match in unchecked_blocks:
            findings.append({
                'type': 'unchecked_arithmetic',
                'severity': 'MEDIUM',
                'message': "Unchecked block found - arithmetic operations may overflow",
                'confidence': 0.8,
                'line': body[:match.start()].count('\n') + 1,
                'fix_suggestion': "Ensure arithmetic in unchecked blocks is safe or add explicit checks"
            })
        
        return findings
    
    def analyze_access_control(self, function: Dict) -> List[Dict]:
        """Анализ контроля доступа"""
        findings = []
        body = function['body']
        signature = function['signature'].lower()
        
        # Критические операции без модификаторов
        critical_operations = [
            (r'\.transfer\([^)]*\)', 'funds_transfer'),
            (r'\.call\{[^}]*value:[^}]*\}', 'funds_transfer'),
            (r'selfdestruct\([^)]*\)', 'selfdestruct'),
            (r'\.delegatecall\([^)]*\)', 'delegatecall'),
            (r'\.mint\([^)]*\)', 'mint_tokens'),
            (r'\.burn\([^)]*\)', 'burn_tokens')
        ]
        
        for pattern, op_type in critical_operations:
            if re.search(pattern, body, re.IGNORECASE):
                # Проверяем наличие модификаторов контроля доступа
                has_access_control = any(mod in signature for mod in [
                    'onlyowner', 'onlyowner', 'modifier', 'require(msg.sender',
                    'require(msg.sender == owner', 'require(hasRole'
                ])
                
                if not has_access_control:
                    findings.append({
                        'type': 'access_control',
                        'severity': 'HIGH',
                        'message': f"Critical operation {op_type} without access control",
                        'confidence': 0.8,
                        'line': 0,
                        'fix_suggestion': "Add access control modifiers or require() statements"
                    })
        
        return findings
    
    def analyze_gas_issues(self, function: Dict) -> List[Dict]:
        """Анализ проблем с газом"""
        findings = []
        body = function['body']
        
        # Бесконечные циклы
        if re.search(r'(for|while)\s*\([^)]*true[^)]*\)', body, re.IGNORECASE):
            findings.append({
                'type': 'infinite_loop',
                'severity': 'HIGH',
                'message': "Potential infinite loop detected",
                'confidence': 0.7,
                'line': 0,
                'fix_suggestion': "Add loop termination conditions with reasonable limits"
            })
        
        # Очень большие циклы
        large_loops = list(re.finditer(r'(for|while)\s*\([^)]*\)\s*\{', body, re.IGNORECASE))
        for loop in large_loops:
            loop_body = self._extract_loop_body(body, loop.end())
            if loop_body and len(loop_body) > 1000:  # Большое тело цикла
                findings.append({
                    'type': 'gas_heavy_loop',
                    'severity': 'MEDIUM',
                    'message': "Potentially gas-heavy loop with large body",
                    'confidence': 0.6,
                    'line': body[:loop.start()].count('\n') + 1,
                    'fix_suggestion': "Optimize loop or consider pagination pattern"
                })
        
        return findings
    
    def _get_context(self, text: str, position: int, length: int) -> str:
        """Получает контекст вокруг позиции"""
        start = max(0, position - length)
        end = min(len(text), position + length)
        return text[start:end]
    
    def _has_safety_checks(self, context: str) -> bool:
        """Проверяет наличие проверок безопасности"""
        safety_indicators = [
            'require(',
            'assert(',
            'if (',
            'safemath',
            'safeadd',
            'safesub'
        ]
        return any(indicator in context.lower() for indicator in safety_indicators)
    
    def _extract_loop_body(self, body: str, start_pos: int) -> str:
        """Извлекает тело цикла"""
        brace_count = 1
        i = start_pos
        while i < len(body) and brace_count > 0:
            if body[i] == '{':
                brace_count += 1
            elif body[i] == '}':
                brace_count -= 1
            i += 1
        return body[start_pos:i-1] if brace_count == 0 else None

class EnhancedScanner:
    """Улучшенный главный сканер"""
    
    def __init__(self):
        self.parser = SolidityParser()
        self.analyzer = AdvancedSecurityAnalyzer()
    
    def analyze_source(self, source_code: str) -> Dict[str, Any]:
        """Главная функция анализа"""
        result = {
            'pragma': self.parser.find_pragma(source_code),
            'contracts': [],
            'functions': [],
            'summary': {
                'total_issues': 0,
                'high_issues': 0,
                'medium_issues': 0,
                'low_issues': 0
            },
            'global_findings': []
        }
        
        # Извлекаем контракты
        contracts = self.parser.extract_contracts(source_code)
        
        for contract in contracts:
            contract_result = {
                'name': contract['name'],
                'type': contract['type'],
                'functions': []
            }
            
            # Анализируем функции в контракте
            functions = self.parser.extract_functions(contract['full_content'])
            
            for function in functions:
                func_analysis = {
                    'name': function['name'],
                    'signature': function['signature'],
                    'findings': [],
                    'snippet': function['body'][:1000]
                }
                
                # Запускаем все анализаторы
                func_analysis['findings'].extend(
                    self.analyzer.analyze_reentrancy(function)
                )
                func_analysis['findings'].extend(
                    self.analyzer.analyze_overflow(function, result['pragma'])
                )
                func_analysis['findings'].extend(
                    self.analyzer.analyze_access_control(function)
                )
                func_analysis['findings'].extend(
                    self.analyzer.analyze_gas_issues(function)
                )
                
                contract_result['functions'].append(func_analysis)
                
                # Обновляем summary
                for finding in func_analysis['findings']:
                    result['summary']['total_issues'] += 1
                    if finding['severity'] == 'HIGH':
                        result['summary']['high_issues'] += 1
                    elif finding['severity'] == 'MEDIUM':
                        result['summary']['medium_issues'] += 1
                    else:
                        result['summary']['low_issues'] += 1
            
            result['contracts'].append(contract_result)
        
        # Глобальные проверки
        self._add_global_findings(source_code, result)
        
        return result
    
    def _add_global_findings(self, source_code: str, result: Dict):
        """Добавляет глобальные находки"""
        # Проверка лицензии
        if 'SPDX-License-Identifier' not in source_code:
            result['global_findings'].append({
                'type': 'license',
                'severity': 'LOW',
                'message': "No SPDX license identifier found",
                'suggestion': "Add SPDX-License-Identifier comment"
            })
        
        # Проверка версии компилятора
        if result['pragma'] == 'unknown':
            result['global_findings'].append({
                'type': 'compiler',
                'severity': 'MEDIUM', 
                'message': "No pragma solidity version specified",
                'suggestion': "Add pragma solidity version for reproducibility"
            })

# Улучшенные фиксы
FIX_SUGGESTIONS = {
    'reentrancy': {
        'title': 'Reentrancy Protection',
        'solutions': [
            "Use Checks-Effects-Interactions pattern",
            "Implement ReentrancyGuard from OpenZeppelin", 
            "Use pull payment pattern instead of push"
        ]
    },
    'overflow': {
        'title': 'Arithmetic Overflow Protection',
        'solutions': [
            "Upgrade to Solidity ^0.8.0 for built-in overflow checks",
            "Use SafeMath library for arithmetic operations",
            "Add explicit require() checks for arithmetic boundaries"
        ]
    }
}

# Пример использования
if __name__ == '__main__':
    scanner = EnhancedScanner()
    
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
    }
    """
    
    result = scanner.analyze_source(test_code)
    print(json.dumps(result, indent=2, ensure_ascii=False))
