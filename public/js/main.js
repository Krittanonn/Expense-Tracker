const getToken = () => {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'login.html';
    }
    return token;
};

// ดึงรายการธุรกรรม
const fetchTransactions = async (category = 'all', type = 'all', startDate = '', endDate = '') => {
    const token = getToken(); // ดึง token ที่ตรวจสอบแล้ว

    try {
        const url = new URL('http://localhost:3001/api/transactions');
        const params = new URLSearchParams();
        if (category !== 'all') params.append('category', category);
        if (type !== 'all') params.append('type', type);
        if (startDate) params.append('startDate', startDate);
        if (endDate) params.append('endDate', endDate);
        
        url.search = params.toString();

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            alert('Error: ' + errorData.message);
            return;
        }

        const transactions = await response.json();
        renderTransactions(transactions); // แสดงรายการธุรกรรมที่ดึงมา
    } catch (error) {
        console.error('Error fetching transactions:', error);
        alert('An error occurred while fetching your transactions.');
    }
};

// ฟังก์ชันกรองข้อมูล
const filterTransactions = (transactions, typeFilter, categoryFilter) => {
    return transactions.filter(transaction => {
        const typeMatch = typeFilter === 'all' || transaction.type === typeFilter;
        const categoryMatch = categoryFilter === 'all' || transaction.category === categoryFilter;
        return typeMatch && categoryMatch;
    });
};

// ฟังก์ชันแสดงรายการ transaction ในตาราง
const renderTransactions = (transactions) => {
    const transactionsTable = document.querySelector('#transactions-table tbody');
    transactionsTable.innerHTML = ''; // เคลียร์ข้อมูลเดิม

    transactions.forEach(transaction => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${transaction.name}</td>
            <td>${transaction.amount}</td>
            <td>${transaction.type}</td>
            <td>${transaction.category}</td>
            <td>${new Date(transaction.date).toLocaleString()}</td>
            <td><button class="delete-btn" data-id="${transaction.id}">Delete</button></td>
        `;
        transactionsTable.appendChild(row);
    });

    // เพิ่ม event listener สำหรับปุ่มลบ
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', async (event) => {
            const transactionId = button.getAttribute('data-id');
            await deleteTransaction(transactionId);
        });
    });
};

// ฟังก์ชันลบรายการธุรกรรม
async function deleteTransaction(id) {
    const token = getToken(); 

    try {
        const response = await fetch(`http://localhost:3001/api/transactions/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();
        
        // เพิ่มการตรวจสอบสถานะการตอบกลับ
        if (response.ok) {
            // alert('Transaction deleted successfully!');
            window.location.reload(); 
        } else {
            // แสดงข้อความผิดพลาดที่ได้รับจากเซิร์ฟเวอร์
            // alert(data.message || 'Failed to delete transaction');
        }
    } catch (error) {
        console.error('Error deleting transaction:', error);
        // alert('An error occurred while deleting the transaction.');
    }
}

// เมื่อกดปุ่มออกจากระบบ
document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('token');  // ลบ token จาก localStorage
    window.location.href = 'login.html';  // ไปที่หน้า login
});

// เมื่อกดปุ่มเพิ่มรายการ
document.getElementById('add-transaction-btn').addEventListener('click', () => {
    window.location.href = 'add-transaction.html';  // ไปหน้าเพิ่มรายการ
});

// ฟังก์ชันกรองข้อมูลและเรียก fetchTransactions
const applyFilters = async () => {
    const typeFilter = document.getElementById('type-filter').value;
    const categoryFilter = document.getElementById('category-filter').value;
    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;
    
    await fetchTransactions(categoryFilter, typeFilter, startDate, endDate);
};

// เมื่อมีการเปลี่ยนแปลงค่าใน select element ให้เรียกฟังก์ชัน applyFilters
document.getElementById('type-filter').addEventListener('change', applyFilters);
document.getElementById('category-filter').addEventListener('change', applyFilters);
document.getElementById('start-date').addEventListener('change', applyFilters);
document.getElementById('end-date').addEventListener('change', applyFilters);

// เรียกใช้ฟังก์ชันเพื่อดึงรายการ transaction และยอดรวมเมื่อหน้าโหลด
document.addEventListener('DOMContentLoaded', () => {
    applyFilters(); // ใช้ฟังก์ชัน applyFilters แทน
    fetchSummary(); // เรียกฟังก์ชันดึงยอดรวม
});

const fetchSummary = async () => {
    const token = getToken(); // ดึง token ที่ตรวจสอบแล้ว

    try {
        const response = await fetch('http://localhost:3001/api/summary', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Error fetching summary:', errorData);
            alert('Error: ' + errorData.message);
            return;
        }

        const summary = await response.json();
        console.log('Summary:', summary); // ตรวจสอบว่าได้รับข้อมูลหรือไม่

        // ตรวจสอบและอัพเดตตัวเลข
        document.getElementById('total-income').textContent = `Total Income: ${summary.total_income} THB`;
        document.getElementById('total-expense').textContent = `Total Expense: ${summary.total_expense} THB`;

    } catch (error) {
        console.error('Error fetching summary:', error);
        alert('An error occurred while fetching your summary.');
    }
};

// ฟังก์ชันแสดงยอดรวม
const renderSummary = (summary) => {
    // ตรวจสอบว่าค่าของ total_income และ total_expense เป็นตัวเลขก่อน
    const totalIncome = (summary.total_income && !isNaN(summary.total_income)) ? summary.total_income.toFixed(2) : '0.00';
    const totalExpense = (summary.total_expense && !isNaN(summary.total_expense)) ? summary.total_expense.toFixed(2) : '0.00';

    document.getElementById('total-income').innerText = `Total Income: ${totalIncome} THB`;
    document.getElementById('total-expense').innerText = `Total Expense: ${totalExpense} THB`;
};

document.getElementById('chart-btn').addEventListener('click', () => {
    window.location.href = 'chart.html';
});
