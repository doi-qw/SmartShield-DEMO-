document.addEventListener('DOMContentLoaded', () => {
  const runBtn = document.getElementById('run');
  const pasteBtn = document.getElementById('paste-example');
  const codeEl = document.getElementById('code');
  const resultBox = document.getElementById('result');
  const logEl = document.getElementById('log');

  // Простая функция для примера кода
  pasteBtn.addEventListener('click', () => {
    codeEl.value = `pragma solidity ^0.7.0;
contract Test {
    mapping(address => uint) public balance;
    
    function withdraw() public {
        (bool ok, ) = msg.sender.call{value: balance[msg.sender]}("");
        balance[msg.sender] = 0;
    }
}`;
  });

  // Упрощенная версия сканирования
  runBtn.addEventListener('click', function() {
    console.log('Кнопка нажата!');
    
    const code = codeEl.value.trim();
    if (!code) {
      alert('Вставь код контракта');
      return;
    }
    
    // Показываем загрузку
    runBtn.disabled = true;
    runBtn.textContent = 'Сканирую...';
    logEl.innerHTML = 'Загружаю...';
    resultBox.classList.remove('hidden');

    // Делаем запрос
    fetch('/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ code: code })
    })
    .then(response => {
      console.log('Статус ответа:', response.status);
      if (!response.ok) {
        throw new Error('Ошибка сервера: ' + response.status);
      }
      return response.json();
    })
    .then(data => {
      console.log('Получены данные:', data);
      showResult(data);
    })
    .catch(error => {
      console.error('Ошибка:', error);
      logEl.innerHTML = '<div class="issue">Ошибка: ' + error.message + '</div>';
    })
    .finally(() => {
      runBtn.disabled = false;
      runBtn.textContent = 'Начать проверку';
    });
  });

  function showResult(data) {
    let html = '';
    
    if (data.pragma) {
      html += `<div><strong>Pragma:</strong> ${data.pragma}</div>`;
    }
    
    if (data.functions && data.functions.length > 0) {
      data.functions.forEach(func => {
        html += `<div class="issue">
          <strong>Function:</strong> ${func.function}<br>
          <strong>Issues:</strong>
          <ul>${func.issues.map(issue => `<li>${issue}</li>`).join('')}</ul>
          <div class="snippet">${func.snippet}</div>
        </div>`;
      });
    } else {
      html += '<div class="ok">No issues found (basic scan)</div>';
    }
    
    logEl.innerHTML = html;
  }
});
