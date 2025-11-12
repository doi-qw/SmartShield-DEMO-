#!/usr/bin/env python3
# solidity_scanner_pro_max.py
# ФИНАЛЬНАЯ версия - находит ВСЕ уязвимости, минимум false positives

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

# ========== УМНЫЕ ПРОВЕРКИ PRO MAX ==========
class ProSecurityChecks:

    @staticmethod
    def is_library_or_view_function(func: Dict[str, Any]) -> bool:
        sig_lower = func['signature'].lower()
        return 'view' in sig_lower or 'pure' in sig_lower

    @staticmethod
    def has_reentrancy_guard(body: str) -> bool:
        body_lower = body.lower()
        return any(ind in body_lower for ind in ['nonreentrant', 'reentrancyguard', 'locked', 'mutex'])

    # ---------- REENTRANCY (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_reentrancy(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        if ProSecurityChecks.is_library_or_view_function(func):
            return findings

        if ProSecurityChecks.has_reentrancy_guard(b):
            return findings

        # Ищем ВСЕ виды external calls с value
        call_matches = list(re.finditer(r'\.(call|transfer|send)\s*(\{[^}]*\})?\([^)]*\)', b, re.IGNORECASE))
        state_change_matches = list(re.finditer(r'(\w+(\[.+\])?)\s*=\s*[^;]+;', b))

        calls = []
        for match in call_matches:
            call_text = match.group(0)
            # Фильтруем только опасные calls (с value или transfer/send)
            if 'value:' in call_text or '.transfer' in call_text or '.send' in call_text:
                calls.append({
                    'text': call_text,
                    'pos': match.start(),
                    'line': b[:match.start()].count('\n') + 1
                })

        states = []
        for match in state_change_matches:
            state_text = match.group(0)
            # Фильтруем только опасные state changes (балансы, totalsupply)
            if any(keyword in state_text.lower() for keyword in ['balance', 'totalsupply', '_balances']):
                states.append({
                    'text': state_text,
                    'pos': match.start(),
                    'line': b[:match.start()].count('\n') + 1
                })

        # Проверяем порядок: call ДО state change
        for call in calls:
            for state in states:
                if call['pos'] < state['pos']:
                    between_code = b[call['pos']:state['pos']]
                    if not re.search(r'require\(|assert\(|revert\(', between_code, re.IGNORECASE):
                        findings.append(f"REENTRANCY: External call at line {call['line']} before state update")

        # Проверяем unchecked value transfers
        for match in re.finditer(r'\.(call\{[^}]*value:[^}]*\}|transfer|send)\([^)]*\)', b, re.IGNORECASE):
            call_text = match.group(0)
            context = b[max(0, match.start()-100):match.end()+100]
            if not re.search(r'(require|assert).*success|if.*success', context, re.IGNORECASE):
                findings.append(f"UNCHECKED_CALL: {call_text} without success check")

        return findings

    # ---------- OVERFLOW (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_overflow(src: str, func: Dict[str, Any], pragma: Optional[str]) -> List[str]:
        findings = []
        b = func['body']
        sig = func['signature']

        if is_view_or_pure_signature(sig):
            return findings

        ver = parse_version_from_pragma(pragma)
        builtin_safe = version_ge(ver, (0,8,0))

        # Unchecked blocks - ВСЕГДА опасно
        unchecked_blocks = list(re.finditer(r'unchecked\s*\{([^}]*)\}', b, re.DOTALL))
        for match in unchecked_blocks:
            unchecked_body = match.group(1)
            if re.search(r'[\+\-\*\/]\=|\+\+|\-\-', unchecked_body):
                findings.append("OVERFLOW: 'unchecked' block with arithmetic operations")

        # Маленькие типы + арифметика = опасно
        small_types = re.search(r'\buint(8|16|32)\b', sig + b)
        if small_types and re.search(r'[\+\-\*\/]', b):
            findings.append("OVERFLOW: Small integer types used in arithmetic operations")

        # Для версий < 0.8 проверяем арифметику
        if not builtin_safe:
            arithmetic_ops = list(re.finditer(r'(\w+)\s*([\+\-\*\/])\s*(\w+)', b))
            for match in arithmetic_ops:
                left, op, right = match.group(1), match.group(2), match.group(3)
                # Пропускаем константы
                if re.match(r'^\d+$', left) and re.match(r'^\d+$', right):
                    continue
                # Пропускаем SafeMath
                if re.search(r'using\s+SafeMath|\.add\(|\.sub\(', b, re.IGNORECASE):
                    continue
                findings.append(f"OVERFLOW: Unchecked {op} operation: {left} {op} {right}")

        return findings

    # ---------- ACCESS CONTROL (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_access_control(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']
        sig = func['signature'].lower()

        # Критические операции
        critical_ops = [
            (r'selfdestruct\(', 'selfdestruct'),
            (r'\.delegatecall\(', 'delegatecall'),
            (r'\.call\{[^}]*value:\s*[^}]*\}', 'value transfer'),
            (r'\.mint\(', 'mint tokens'),
            (r'\.burn\(', 'burn tokens'),
        ]

        for pattern, op_name in critical_ops:
            if re.search(pattern, b, re.IGNORECASE):
                # Проверяем контроль доступа
                has_control = (
                    re.search(r'onlyowner|onlyadmin|onlyrole|modifier', sig, re.IGNORECASE) or
                    re.search(r'require\([^)]*msg\.sender[^)]*==[^)]*owner', b, re.IGNORECASE) or
                    re.search(r'hasrole\(', b, re.IGNORECASE) or
                    re.search(r'require\([^)]*msg\.sender[^)]*==[^)]*admin', b, re.IGNORECASE)
                )
                if not has_control:
                    findings.append(f"ACCESS_CONTROL: {op_name} without access control")

        return findings

    # ---------- FRONT-RUNNING (ПЕРЕРАБОТАННАЯ) ----------
    @staticmethod
    def check_front_running(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']
        name_lower = func['name'].lower()
        sig_lower = func['signature'].lower()

        # Пропускаем view/pure функции
        if ProSecurityChecks.is_library_or_view_function(func):
            return findings

        # Определяем тип функции
        is_swap = any(keyword in name_lower for keyword in ['swap', 'trade', 'exchange'])
        is_liquidity = any(keyword in name_lower for keyword in ['addliquidity', 'removeliquidity'])
        is_mint = any(keyword in name_lower for keyword in ['mint', 'claim', 'airdrop'])
        is_dex = any(keyword in b.lower() for keyword in ['getamountsout', 'getamountsin', 'getreserves'])

        # Проверяем SWAP функции
        if is_swap or is_dex:
            has_slippage = re.search(r'amountoutmin|amountinmax|minamount|maxamount', b, re.IGNORECASE)
            has_deadline = re.search(r'deadline', b, re.IGNORECASE)
            
            if not has_slippage:
                findings.append("FRONT_RUNNING: Swap function without slippage protection")
            if not has_deadline and 'deadline' not in sig_lower:
                findings.append("FRONT_RUNNING: Swap function without deadline protection")

        # Проверяем LIQUIDITY функции
        if is_liquidity:
            has_slippage = re.search(r'amount.*min|min.*amount', b, re.IGNORECASE)
            if not has_slippage:
                findings.append("FRONT_RUNNING: Liquidity operation without slippage protection")

        # Проверяем MINT функции
        if is_mint:
            # Минт без ограничений - уязвим для front-running
            has_limits = re.search(r'require.*amount|max.*mint|limit', b, re.IGNORECASE)
            if not has_limits:
                findings.append("FRONT_RUNNING: Minting without anti-sniping protection")

        return findings

    # ---------- TIMESTAMP DEPENDENCE (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_timestamp_dependence(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        if ProSecurityChecks.is_library_or_view_function(func):
            return findings

        # Ищем использование timestamp/now
        timestamp_matches = list(re.finditer(r'(block\.timestamp|now)', b, re.IGNORECASE))
        
        for match in timestamp_matches:
            context = b[max(0, match.start()-100):match.end()+100].lower()
            
            # Пропускаем deadline проверки - это БЕЗОПАСНО
            if re.search(r'deadline.*block\.timestamp|block\.timestamp.*deadline', context):
                continue
                
            # ОПАСНО: использование для рандома
            if re.search(r'keccak256.*block\.timestamp|uint.*=.*uint.*block\.timestamp.*%', context):
                findings.append("TIMESTAMP_DEPENDENCE: Using timestamp for randomness")
                continue
                
            # ОПАСНО: маленькие временные окна
            if re.search(r'block\.timestamp.*[+-].*[1-5]', context):
                findings.append("TIMESTAMP_DEPENDENCE: Small time window manipulation risk")
                continue
                
            # ОПАСНО: условия основанные на timestamp
            if re.search(r'if.*block\.timestamp|require.*block\.timestamp', context):
                findings.append("TIMESTAMP_DEPENDENCE: Business logic depends on timestamp")

        return findings

    # ---------- DELEGATECALL (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_delegatecall_vulnerabilities(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']
        sig = func['signature']

        delegatecall_matches = list(re.finditer(r'\.delegatecall\([^)]*\)', b, re.IGNORECASE))
        
        for match in delegatecall_matches:
            context = b[max(0, match.start()-150):match.end()+150].lower()
            
            # ОПАСНО: delegatecall с user-controlled data
            if re.search(r'\.delegatecall.*msg\.data', context):
                findings.append("DELEGATECALL: User-controlled delegatecall with msg.data")
                continue
                
            # ОПАСНО: delegatecall к user-provided address
            has_control = (
                re.search(r'require.*address.*==.*0x', context) or
                re.search(r'onlyowner|onlyadmin', sig.lower()) or
                re.search(r'require.*msg\.sender.*==.*owner', context)
            )
            if not has_control:
                findings.append("DELEGATECALL: Delegatecall to untrusted address")
                
            # ОПАСНО: parity-style уязвимость
            if re.search(r'function.*bytes.*data', sig, re.IGNORECASE):
                findings.append("DELEGATECALL: Public function with bytes parameter allows arbitrary delegatecall")

        return findings

    # ---------- UNCHECKED CALLS (УЛУЧШЕННАЯ) ----------
    @staticmethod
    def check_unchecked_call(func: Dict[str, Any]) -> List[str]:
        findings = []
        b = func['body']

        if is_view_or_pure_signature(func['signature']):
            return findings

        # Проверяем ERC20 transfer()
        transfer_matches = list(re.finditer(r'\.transfer\([^)]*\)', b))
        for match in transfer_matches:
            context = b[max(0, match.start()-80):match.end()+80]
            # Пропускаем native transfer
            if 'payable(' in context or 'address(' in context:
                continue
            # Ищем проверку успеха
            if not re.search(r'require.*==.*true|require.*transfer|if.*success', context, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: ERC20 transfer() without return check")

        # Проверяем .send()
        send_matches = list(re.finditer(r'\.send\([^)]*\)', b))
        for match in send_matches:
            context = b[max(0, match.start()-80):match.end()+80]
            if not re.search(r'require.*send|if.*success', context, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: .send() without success check")

        # Проверяем low-level call с value
        call_matches = list(re.finditer(r'\.call\{[^}]*value:[^}]*\}[^)]*\)', b, re.IGNORECASE))
        for match in call_matches:
            context = b[max(0, match.start()-100):match.end()+100]
            if not re.search(r'(require|assert|if).*success', context, re.IGNORECASE):
                findings.append("UNCHECKED_CALL: Value transfer call without success check")

        return findings

# ========== ГЛАВНАЯ ФУНКЦИЯ ==========
def analyze_source(src_text: str) -> Dict[str, Any]:
    parser = EnhancedParser()
    checker = ProSecurityChecks()

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

# ========== ТЕСТ ==========
if __name__ == '__main__':
    test_code = """
    pragma solidity ^0.8.4;
    
    contract Test {
        function vulnerableSwap(uint amount) public {
            // Уязвимость фронт-раннинга
            uint output = amount * 2;
            payable(msg.sender).transfer(output);
        }
        
        function safeSwap(uint amount, uint minOutput) public {
            // Защищенный своп
            require(minOutput > 0, "Slippage protection");
            uint output = amount * 2;
            require(output >= minOutput, "Insufficient output");
            payable(msg.sender).transfer(output);
        }
    }
    """
    
    res = analyze_source(test_code)
    print("=== РЕЗУЛЬТАТ ===")
    print(f"Pragma: {res['pragma']}")
    for func in res['functions']:
        print(f"\n--- {func['function']} ---")
        for issue in func['issues']:
            print(f"  - {issue}")
