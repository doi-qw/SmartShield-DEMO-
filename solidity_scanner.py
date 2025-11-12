#!/usr/bin/env python3
# solidity_scanner_perfected.py
# ИДЕАЛЬНАЯ версия сканера - минимум ложных срабатываний, максимум точности

import re
import json
from typing import List, Dict, Any, Optional, Tuple

# ========== УТИЛИТЫ ==========
def parse_version_from_pragma(pragma: Optional[str]) -> Optional[Tuple[int,int,int]]:
    if not pragma:
        return None
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', pragma)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)

def version_ge(v: Optional[Tuple[int,int,int]], target=(0,8,0)) -> bool:
    if not v:
        return False
    return v >= target

def is_view_or_pure_signature(sig: str) -> bool:
    s = sig.lower()
    return ' view' in s or ' pure' in s or s.strip().endswith('view') or s.strip().endswith('pure')

def is_library_function(sig: str, body: str) -> bool:
    sig_lower = sig.lower()
    body_lower = body.lower()
    return 'library' in sig_lower or 'internal' in sig_lower and not 'public' in sig_lower and not 'external' in sig_lower

# ========== УЛУЧШЕННЫЙ ПАРСЕР ==========
class EnhancedParser:
    @staticmethod
    def find_pragma(content: str) -> Optional[str]:
        m = re.search(r'pragma\s+solidity\s+([^;]+);', content)
        return m.group(1).strip() if m else None

    @staticmethod
    def extract_functions(src: str) -> List[Dict[str, Any]]:
        funcs = []
        pattern = re.compile(
            r'(function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^\)]*\)\s*(?:public|private|internal|external|constant|payable|view|pure|\s|modifier|returns\([^\)]*\))*?)\{',
            re.S
        )
        for m in pattern.finditer(src):
            sig_start = m.start(1)
            sig = m.group(1)
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
                        name_match = re.search(r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)', sig)
                        func_name = name_match.group(1) if name_match else "<unknown>"
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

# ========== УМНЫЕ ПРОВЕРКИ С МИНИМУМОМ FALSE POSITIVES ==========
class SmartSecurityChecks:

    @staticmethod
    def is_library_or_view_function(func: Dict[str, Any]) -> bool:
        sig_lower = func['signature'].lower()
        body_lower = func['body'].lower()
        return ('view' in sig_lower or 'pure' in sig_lower or 
                'library' in sig_lower or is_library_function(func['signature'], func['body']))

    @staticmethod
    def has_reentrancy_guard(body: str) -> bool:
        reentrancy_indicators = [
            'nonReentrant',
            'reentrancyguard',
            'locked',
            'mutex',
            'noreentrancy',
            'noReentrancy'
        ]
        body_lower = body.lower()
        return any(ind in body_lower for ind in reentrancy_indicators)

    @staticmethod
    def is_safe_arithmetic_context(context: str) -> bool:
        ctx = context.lower()
        safe_indicators = [
            'require(',
            'assert(',
            'if (',
            'safemath',
            '.add(',
            '.sub(',
            '.mul(',
            '.div(',
            'unchecked',
            'using safemath'
        ]
        return any(ind in ctx for ind in safe_indicators)

    @staticmethod
    def is_safe_loop_arithmetic(operation: str, context: str) -> bool:
        """Проверяет безопасные арифметические операции в циклах"""
        # Безопасно если: for (uint i = 0; i < CONSTANT; i++)
        loop_patterns = [
            r'for\s*\(\s*\w+\s+\w+\s*=\s*\d+\s*;\s*\w+\s*[<>=]=\s*\d+\s*;',
            r'for\s*\(\s*\w+\s+\w+\s*=\s*\d+\s*;\s*\w+\s*<\s*\d+\s*;',
            r'for\s*\(\s*\w+\s+\w+\s*=\s*\d+\s*;\s*\w+\s*<=\s*\d+\s*;',
            r'while\s*\(\s*\w+\s*<\s*\d+\s*\)',
        ]
        
        # Проверяем фиксированные границы циклов
        for pattern in loop_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        # Безопасно если операция с константами: i * 2, i + 1 и т.д.
        constant_ops = [
            r'\w+\s*\*\s*\d+',
            r'\w+\s*\+\s*\d+', 
            r'\w+\s*-\s*\d+',
            r'\d+\s*\*\s*\w+',
        ]
        
        for pattern in constant_ops:
            if re.search(pattern, operation):
                return True
                
        return False

    @staticmethod
    def is_safe_operation_pattern(operation: str, context: str) -> bool:
        """Распознает безопасные паттерны операций"""
        safe_patterns = [
            r'block\.number\s*-\s*\d+',          # block.number - 1
            r'block\.timestamp\s*[+-]\s*\d+',    # timestamp с константой
            r'\w+\s*=\s*\w+\s*\+\s*\d+',         # variable + constant
            r'\w+\s*=\s*\w+\s*\*\s*\d+',         # variable * constant
            r'\w+\s*=\s*\d+\s*\*\s*\w+',         # constant * variable
            r'address\([^)]*\)\.balance',        # чтение баланса
            r'bytes32\([^)]*\)',                 # конвертация в bytes32
            r'uint256\([^)]*\)',                 # конвертация в uint256
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, context):
                return True
                
        # Безопасные ассемблерные операции
        safe_assembly = [
            r'mload\(',
            r'mstore\(',
            r'add\(',
            r'and\(',
            r'shl\(',
            r'shr\(',
            r'calldatasize\(\)',
            r'calldataload\(',
        ]
        
        if 'assembly' in context:
            for pattern in safe_assembly:
                if re.search(pattern, context):
                    return True
                    
        return False

    @staticmethod
    def is_potential_front_running_function(func: Dict[str, Any]) -> bool:
        """Определяет может ли функция быть подвержена front-running"""
        name_lower = func['name'].lower()
        sig_lower = func['signature'].lower()
        body_lower = func['body'].lower()
        
        # Только определенные типы функций могут быть front-run
        front_run_keywords = ['swap', 'trade', 'mint', 'addliquidity', 'removeliquidity', 'buy', 'sell']
        
        if not any(keyword in name_lower for keyword in front_run_keywords):
            return False
            
        # View/pure функции не могут быть front-run
        if SmartSecurityChecks.is_library_or_view_function(func):
            return False
            
        # Функции без payable/state changes вряд ли будут front-run
        if 'payable' not in sig_lower and not re.search(r'=\s*[^;]+;', body_lower):
            return False
            
        return True

    # ---------- REENTRANCY ----------
    @staticmethod
    def check_reentrancy(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        if SmartSecurityChecks.is_library_or_view_function(func):
            return findings

        if SmartSecurityChecks.has_reentrancy_guard(b):
            return findings

        call_patterns = [
            r'\.call\{[^}]*\}[^)]*\)',
            r'\.transfer\([^)]*\)',
            r'\.send\([^)]*\)',
        ]

        state_patterns = [
            r'\w+\[[^\]]*\]\s*=\s*[^;]+;',
            r'\w+\s*=\s*[^;]+;',
            r'\btotalSupply\b\s*[\+\-]=',
        ]

        calls = []
        for pattern in call_patterns:
            for match in re.finditer(pattern, b, re.IGNORECASE):
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
                    if not re.search(r'require\(|assert\(|revert\(', between_code, re.IGNORECASE):
                        findings.append(f"REENTRANCY: External call at line {call['line']} before state update at line {state['line']}")

        for match in re.finditer(r'(\w+)\.call\{[^}]*value:\s*[^}]*\}[^)]*\)', b, re.IGNORECASE):
            ctx_start = max(0, match.start() - 120)
            ctx_end = min(len(b), match.end() + 120)
            ctx = b[ctx_start:ctx_end]
            if not re.search(r'(require\(|if\s*\(.*success|assert\()', ctx, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: Value transfer call without success check")

        return findings

    # ---------- OVERFLOW (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_overflow(src: str, func: Dict[str, Any], pragma: Optional[str]) -> List[str]:
        findings = []
        b = func['body']
        sig = func['signature']

        ver = parse_version_from_pragma(pragma)
        builtin_safe = version_ge(ver, (0,8,0))

        if is_view_or_pure_signature(sig) or SmartSecurityChecks.is_library_or_view_function(func):
            return findings

        using_safemath = re.search(r'using\s+SafeMath|using\s+safemath', src, re.IGNORECASE) is not None
        library_safe_ops = re.search(r'\.add\(|\.sub\(|\.mul\(', b) is not None

        # Unchecked blocks - всегда проверяем
        for match in re.finditer(r'unchecked\s*\{([^}]*)\}', b, re.DOTALL):
            unchecked_body = match.group(1)
            if re.search(r'[\+\-\*\/]\=|[\+\-\*\/]\s|\+\+|\-\-', unchecked_body):
                findings.append("OVERFLOW: 'unchecked' block with arithmetic operations")

        small_types = re.search(r'\buint(8|16|32)\b', sig + b) is not None

        arithmetic_patterns = [
            (r'([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)', 'addition'),
            (r'([A-Za-z_][A-Za-z0-9_]*)\s*\-\s*([A-Za-z_][A-Za-z0-9_]*)', 'subtraction'),
            (r'([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)', 'multiplication'),
        ]

        for pattern, op_type in arithmetic_patterns:
            for match in re.finditer(pattern, b):
                left, right = match.group(1), match.group(2)
                span = match.group(0)
                
                # Пропускаем константы
                if re.match(r'^\d+$', left) and re.match(r'^\d+$', right):
                    continue

                context_start = max(0, match.start() - 150)
                context_end = min(len(b), match.end() + 150)
                context = b[context_start:context_end]

                # Пропускаем безопасные контексты
                if (using_safemath or library_safe_ops or 
                    SmartSecurityChecks.is_safe_arithmetic_context(context) or
                    SmartSecurityChecks.is_safe_loop_arithmetic(span, context) or
                    SmartSecurityChecks.is_safe_operation_pattern(span, context)):
                    continue

                # Пропускаем если компилятор имеет встроенную защиту
                if builtin_safe and not small_types:
                    continue

                findings.append(f"OVERFLOW: Unchecked {op_type} operation: {span.strip()}")

        if small_types and re.search(r'[\+\-\*\/]', b):
            findings.append("OVERFLOW: Small integer types used in arithmetic operations")

        return findings

    # ---------- UNCHECKED CALL ----------
    @staticmethod
    def check_unchecked_call(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        if is_view_or_pure_signature(func['signature']):
            return findings

        for match in re.finditer(r'([A-Za-z_][A-Za-z0-9_\.]*)\.transfer\([^)]*\)', b):
            full = match.group(0)
            ctx_start = max(0, match.start() - 60)
            ctx = b[ctx_start:match.end()].lower()
            if 'payable(' in ctx or '.call{' in ctx or 'address(' in ctx:
                continue
            check_ctx = b[max(0, match.start()-120):min(len(b), match.end()+120)]
            if not re.search(r'(require\(|if\s*\(.*success|assert\(|require\(\s*.*==\s*true)', check_ctx, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: ERC20 transfer() without return value check")

        for match in re.finditer(r'\.call\{[^}]*value:\s*[^}]*\}[^)]*\)', b, re.IGNORECASE):
            ctx = b[max(0, match.start()-120):match.end()+120]
            if not re.search(r'(if\s*\(.*success|require\(|assert\()', ctx, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: Value transfer call without success check")

        return findings

    # ---------- ACCESS CONTROL ----------
    @staticmethod
    def check_access_control(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']
        sig = func['signature'].lower()

        critical_ops = [
            (r'selfdestruct\(', 'selfdestruct'),
            (r'\.delegatecall\(', 'delegatecall'),
        ]

        for pattern, op_name in critical_ops:
            if re.search(pattern, b, re.IGNORECASE):
                has_modifier = re.search(r'onlyowner|onlyadmin|onlyrole|modifier', sig, re.IGNORECASE) is not None
                has_require_check = re.search(r'require\([^)]*msg\.sender[^)]*==[^)]*owner', b, re.IGNORECASE) is not None
                has_role_check = re.search(r'hasrole\(', b, re.IGNORECASE) is not None
                if not (has_modifier or has_require_check or has_role_check):
                    findings.append(f"ACCESS_CONTROL: Critical operation '{op_name}' without access control")

        return findings

    # ---------- FRONT-RUNNING (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_front_running(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        # Проверяем только потенциально уязвимые функции
        if not SmartSecurityChecks.is_potential_front_running_function(func):
            return findings

        front_running_patterns = [
            (r'addLiquidity\([^)]*\)', 'addLiquidity without slippage protection'),
            (r'removeLiquidity\([^)]*\)', 'removeLiquidity without slippage protection'),
            (r'swapExactTokensForTokens\([^)]*\)', 'swap without slippage protection'),
            (r'swapTokensForExactTokens\([^)]*\)', 'swap without slippage protection'),
        ]

        for pattern, description in front_running_patterns:
            if re.search(pattern, b, re.IGNORECASE):
                has_protection = re.search(r'deadline\s*[^=]|amountOutMin|amountInMax|slippage|minAmount|maxAmount', b, re.IGNORECASE) is not None
                if not has_protection:
                    findings.append(f"FRONT_RUNNING: {description}")

        # Более точная проверка для price calculations
        if re.search(r'getReserves\(\)|getAmounts', b) and SmartSecurityChecks.is_potential_front_running_function(func):
            if not re.search(r'(amountOutMin|amountInMax|minAmount|maxAmount)\s*=', b):
                findings.append("FRONT_RUNNING: Price calculation without min/max amount protection")

        return findings

    # ---------- TIMESTAMP DEPENDENCE (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_timestamp_dependence(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        # Пропускаем view функции
        if SmartSecurityChecks.is_library_or_view_function(func):
            return findings

        for match in re.finditer(r'block\.timestamp|now', b, re.IGNORECASE):
            ctx_start = max(0, match.start() - 120)
            ctx_end = min(len(b), match.end() + 120)
            context = b[ctx_start:ctx_end].lower()

            # Пропускаем безопасные использования timestamp
            if SmartSecurityChecks.is_safe_operation_pattern(match.group(), context):
                continue

            if re.search(r'keccak256\([^\)]*block\.timestamp', context) or re.search(r'uint\s*\w*\s*=\s*uint\(keccak256\([^\)]*block\.timestamp', context):
                findings.append("TIMESTAMP_DEPENDENCE: Using timestamp for randomness - miners can manipulate")
                continue

            if re.search(r'block\.timestamp\s*[+\-]\s*\d+\s*;', context) or re.search(r'block\.timestamp.*[+\-].*[1-5]', context):
                findings.append("TIMESTAMP_DEPENDENCE: small time window manipulation risk")
                continue

            if re.search(r'if\s*\([^\)]*block\.timestamp[^\)]*\)', context) or re.search(r'require\(.*block\.timestamp', context):
                findings.append("TIMESTAMP_DEPENDENCE: timestamp in conditional logic")

        if re.search(r'require\(.*block\.timestamp.*[<>]=?\s*\d+', b):
            findings.append("TIMESTAMP_DEPENDENCE: timestamp requirement without buffer")

        return findings

    # ---------- DELEGATECALL ----------
    @staticmethod
    def check_delegatecall_vulnerabilities(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        for match in re.finditer(r'\.delegatecall\([^)]*\)', b, re.IGNORECASE):
            ctx_start = max(0, match.start() - 200)
            ctx_end = min(len(b), match.end() + 200)
            context = b[ctx_start:ctx_end].lower()

            if re.search(r'\.delegatecall.*msg\.data', context):
                findings.append("DELEGATECALL: user-controlled delegatecall with msg.data (dangerous pattern)")

            if not re.search(r'require\(.*address.*==.*0x|require\(.*msg\.sender.*==.*owner|onlyowner|onlyadmin', context, re.IGNORECASE):
                findings.append("DELEGATECALL: Delegatecall to potentially untrusted address")

            if re.search(r'function\s+[a-zA-Z0-9_]+\([^)]*bytes\s+[a-zA-Z0-9_]+', func['signature'], re.IGNORECASE) and 'delegatecall' in context:
                findings.append("DELEGATECALL: Delegatecall exposed via public function accepting bytes (parity-style risk)")

        return findings

# ========== СОВМЕСТИМЫЙ ИНТЕРФЕЙС ==========
def analyze_source(src_text: str) -> Dict[str, Any]:
    parser = EnhancedParser()
    checker = SmartSecurityChecks()

    pragma = parser.find_pragma(src_text)
    funcs = parser.extract_functions(src_text)
    report = []

    for f in funcs:
        f_findings: List[str] = []

        f_findings.extend(checker.check_reentrancy(f))
        f_findings.extend(checker.check_overflow(src_text, f, pragma))
        f_findings.extend(checker.check_unchecked_call(f))
        f_findings.extend(checker.check_access_control(f))
        f_findings.extend(checker.check_front_running(f))
        f_findings.extend(checker.check_timestamp_dependence(f))
        f_findings.extend(checker.check_delegatecall_vulnerabilities(f))

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
    test_code = """
    pragma solidity ^0.8.4;

    contract Test {
        // Безопасные операции которые НЕ должны вызывать предупреждения
        function safeLoop() public pure returns (uint256) {
            uint256 result = 0;
            for (uint256 i = 0; i < 10; i++) {
                result += i * 2;  // БЕЗОПАСНО - фиксированный цикл
            }
            return result;
        }
        
        function safeConstants() public pure returns (uint256) {
            return 5 * 10 + 42;  // БЕЗОПАСНО - только константы
        }
        
        function safeBlockNumber() public view returns (uint256) {
            return block.number - 1;  // БЕЗОПАСНО
        }
        
        // Опасные операции которые ДОЛЖНЫ быть найдены
        function vulnerable(uint256 a, uint256 b) public {
            unchecked {
                balances[msg.sender] -= a;  // ОПАСНО - unchecked
            }
            totalSupply += b;  // ОПАСНО - нет проверки
        }
    }
    """
    
    res = analyze_source(test_code)
    print("Pragma:", res['pragma'])
    print("Functions with findings:", len(res['functions']))
    for func in res['functions']:
        print("\n---", func['function'], "---")
        for issue in func['issues']:
            print(" -", issue)
    for m in res['global_msgs']:
        print(m)
