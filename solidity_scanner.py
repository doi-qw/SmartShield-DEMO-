#!/usr/bin/env python3
# solidity_scanner.py (adapted for web)
# Быстрый эвристический сканер для 3 типов уязвимостей (reentrancy, overflow, unchecked call).
# Адаптирован так, чтобы принимать строку исходника и возвращать структуру Python (dict).

import re

# ---------------- utilities ----------------
def find_pragma(content):
    m = re.search(r'pragma\s+solidity\s+([^;]+);', content)
    return m.group(1).strip() if m else None

def extract_functions(src):
    funcs = []
    pattern = re.compile(r'(function\s+[A-Za-z0-9_]+\s*\([^)]*\)[^{]*){', re.S)
    for m in pattern.finditer(src):
        sig_start = m.start()
        sig = m.group(1)
        brace_pos = m.end()-1
        # найти соответствующую закрывающую скобку
        depth = 0
        i = brace_pos
        while i < len(src):
            if src[i] == '{':
                depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0:
                    body = src[brace_pos+1:i]
                    nm = re.search(r'function\s+([A-Za-z0-9_]+)', sig)
                    name = nm.group(1) if nm else "<unknown>"
                    funcs.append({
                        'name': name,
                        'signature': sig.strip(),
                        'body': body,
                        'start': sig_start,
                        'end': i+1
                    })
                    break
            i += 1
    # also try fallback/receive style if not matched by above (optional)
    return funcs

# ---------------- checks (heuristics) ----------------
def check_reentrancy(func):
    b = func['body']
    findings = []
    call_matches = list(re.finditer(r'\.call\s*(?:\{[^}]*\})?\s*\(|\.\s*transfer\s*\(|\.send\s*\(', b))
    if call_matches:
        state_matches = list(re.finditer(r'\b(balance|balances|mapping|_balances|userState)\b|=[^=]|-=|\+=', b))
        if state_matches:
            first_call = call_matches[0].start()
            first_state = state_matches[0].start()
            if first_call < first_state:
                findings.append("external call appears before state update (possible reentrancy)")
        else:
            if re.search(r'\bfor\s*\(|\bwhile\s*\(', b) and call_matches:
                findings.append("external call inside loop (risk of reentrancy/DoS)")
    if re.search(r'\breceive\s*\(\s*\)\s*external', func['signature']) or 'fallback' in func['signature']:
        if re.search(r'\.call\s*\(|\.transfer\s*\(|\.send\s*\(', b):
            findings.append("receive/fallback performs external calls — usually dangerous")
    return findings

def check_overflow(src, func, pragma):
    findings = []
    try:
        if pragma:
            # очень простая проверка
            if re.search(r'0\.\s*\d+', pragma) or re.search(r'0\.\d+', pragma):
                v = re.search(r'0\.(\d+)', pragma)
                if v and int(v.group(1)) < 8:
                    findings.append("pragma <0.8.0 — переполнение/underflow не защитит компилятор")
            # альтернативный простой матч
            if re.search(r'<\s*0\.8', pragma):
                findings.append("pragma <0.8.0 — переполнение/underflow не защитит компилятор")
    except Exception:
        pass

    b = func['body']
    if re.search(r'\buint(8|16|24|32|40|48|56|64)\b', func['signature'] + b):
        findings.append("используются маленькие целочисленные типы (uint8/..) — риск переполнения/underflow")
    if 'unchecked' in b:
        findings.append("используется 'unchecked' — арифметические операции могут переполняться без revert")
    if re.search(r'for\s*\([^)]*\)\s*{[^}]*\+\=|[^}]*\+[^=]', b, re.S):
        if re.search(r'\b[sS]\s*=\s*[sS]\s*\+\s*[A-Za-z0-9_\[\]]+', b):
            findings.append("сложение в цикле без явной проверки (возможное переполнение при больших входных данных)")
    return findings

def check_unchecked_call(func):
    b = func['body']
    findings = []
    for m in re.finditer(r'([A-Za-z0-9_]+)\.transfer\s*\(', b):
        line_start = b.rfind('\n', 0, m.start())+1
        line_end = b.find('\n', m.end())
        line = b[line_start: line_end if line_end!=-1 else None]
        prev = b[max(0, line_start-200):line_start]
        combined = prev + line
        if 'require(' not in combined and 'bool' not in combined and '.safeTransfer' not in combined:
            findings.append("token.transfer(...) вызов без проверки возвращаемого значения (unchecked ERC20 transfer)")
    if re.search(r'\bcall\s*\(', b):
        if re.search(r'\(.*bool\s+success.*\)\s*=\s*[^;]*\.call', b) and 'require(success' not in b and 'if (success' not in b:
            findings.append("low-level call used and success not checked")
        if re.search(r'[^=]\.call\s*\(', b) and 'require(' not in b:
            findings.append("low-level .call(...) используется без явной проверки результата")
    return findings

# ---------------- fixes templates (по мотивам базы, сокращённо) ----------------
FIX_TEMPLATES = {
    'reentrancy_withdraw': {
        'desc': "Checks-effects-interactions: обновлять состояние до внешнего вызова или использовать pull-payments / ReentrancyGuard.",
        'template': """// Fixed: checks-effects-interactions
function withdraw() external {
    uint256 amt = balance[msg.sender];
    require(amt > 0, "No funds");
    balance[msg.sender] = 0; // effect: state updated BEFORE external call
    (bool ok, ) = msg.sender.call{value: amt}("");
    require(ok, "Transfer failed");
}"""
    },
    'reentrancy_batch': {
        'desc': "Использовать pull pattern: назначать балансы и позволять каждому вызывать withdraw индивидуально.",
        'template': """// Fixed: pull pattern (notify credits and let users withdraw)
function notifyCredits(address[] calldata recipients, uint256[] calldata amounts) external {
    require(recipients.length == amounts.length);
    for (uint i=0;i<recipients.length;i++){
        balance[recipients[i]] += amounts[i];
    }
}
function withdraw() external {
    uint amt = balance[msg.sender];
    require(amt>0);
    balance[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amt}("");
    require(ok);
}"""
    },
    'overflow_safe': {
        'desc': "Для pragma <0.8 использовать SafeMath или перейти на ^0.8.0; избегать uint8 для сумм/монет; проверять диапазоны.",
        'template': """// Fixed (example): использовать uint256 и проверки
function inc(uint256 n) external {
    // explicit check
    require(n <= 1e27, "n too large");
    counter = counter + n;
}"""
    },
    'unchecked_call_return': {
        'desc': "Проверять возвращаемое значение от ERC20 или использовать OpenZeppelin SafeERC20.",
        'template': """// Fixed: check bool result
function pay(IERC20 token, address to, uint256 value) external {
    bool ok = token.transfer(to, value);
    require(ok, "ERC20 transfer failed");
}
// Or using SafeERC20.safeTransfer(token, to, value);
"""
    },
    'lowlevel_call_check': {
        'desc': "Проверять success результата low-level call.",
        'template': """// Fixed: check success
(bool success, bytes memory ret) = target.call(data);
require(success, "external call failed");"""
    }
}

# ---------------- main API ----------------
def analyze_source(src_text):
    """
    Главная функция: принимает строку с исходником и возвращает dict:
    { 'pragma': ..., 'functions': [ {function, signature, issues (list), snippet }, ... ], 'global_msgs': [...] }
    """
    pragma = find_pragma(src_text)
    funcs = extract_functions(src_text)
    report = []
    for f in funcs:
        f_findings = []
        r = check_reentrancy(f)
        o = check_overflow(src_text, f, pragma)
        u = check_unchecked_call(f)
        f_findings.extend(r)
        f_findings.extend(o)
        f_findings.extend(u)
        if f_findings:
            # trim body snippet for UI
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

# Если хочешь, можешь запускать анализ локально (для отладки)
if __name__ == '__main__':
    sample = """
    pragma solidity ^0.7.0;
    contract C {
        mapping(address=>uint) public balance;
        function withdraw() public {
            (bool ok, ) = msg.sender.call{value: balance[msg.sender]}("");
            // state updated after call -- vulnerability
            balance[msg.sender] = 0;
        }
    }"""
    print(analyze_source(sample))
