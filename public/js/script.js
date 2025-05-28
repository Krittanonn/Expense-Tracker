// ส่วนของการลงทะเบียน
document.getElementById('registerForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    const response = await fetch('http://localhost:3001/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password }),
    });

    const data = await response.json();
    if (data.message === 'User registered successfully') {
        window.location.href = 'login.html';
    } else {
        document.getElementById('error-message').innerText = data.message;
    }
});

// ส่วนของการเข้าสู่ระบบ
document.getElementById('loginForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const response = await fetch('http://localhost:3001/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
    });

    const data = await response.json();
    if (data.message === 'Login successful') {
        localStorage.setItem('token', data.token);
        window.location.href = 'transactions.html';
    } else {
        document.getElementById('error-message').innerText = data.message;
    }
});

// ส่วนของการแสดงรายการธุรกรรม
document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    const response = await fetch(`http://localhost:3001/api/transactions?token=${token}`);
    const transactions = await response.json();

    const tableBody = document.querySelector('#transactionTable tbody');
    transactions.forEach(transaction => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${transaction.amount}</td>
            <td>${transaction.type}</td>
            <td>${transaction.category}</td>
            <td>${new Date(transaction.date).toLocaleString()}</td>
        `;
        tableBody.appendChild(row);
    });
});
