document.getElementById('add-transaction-form').addEventListener('submit', async function(event) {
    event.preventDefault();  // ป้องกันการ submit แบบปกติ

    // ดึงค่าจากฟอร์ม
    const name = document.getElementById('name').value;
    const amount = document.getElementById('amount').value;
    const category = document.getElementById('category').value;
    const type = document.querySelector('input[name="type"]:checked')?.value; // ตรวจสอบค่า type จาก radio button
    const date = document.getElementById('date').value; // ดึงค่าจาก input date

    // ตรวจสอบว่ามีการเลือก type หรือไม่
    if (!type) {
        alert('Please select a transaction type (Income or Expense).');
        return;
    }

    // ดึง token ที่บันทึกจากการ login
    let token = localStorage.getItem('token');

    // ตรวจสอบว่า token มีหรือไม่
    if (!token) {
        alert('Please log in first');
        window.location.href = 'login.html';  // ไปหน้า login ถ้าไม่มี token
        return;
    }

    // ข้อมูลที่ส่งไปยัง API
    const transactionData = {
        name,
        amount,
        category,
        type,
        date
    };

    try {
        // ส่งข้อมูลไปยัง API สำหรับเพิ่มรายการ
        let response = await fetch('http://localhost:3001/api/transactions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`  // ส่ง token ไปพร้อมกับคำขอ
            },
            body: JSON.stringify(transactionData)
        });

        let data = await response.json();

        // ตรวจสอบกรณี token หมดอายุ
        if (response.status === 403 && data.message === 'Could not verify token') {
            // ถ้า token หมดอายุ ให้ทำการรีเฟรช token หรือให้ผู้ใช้ล็อกอินใหม่
            alert('Your session has expired. Please log in again.');
            window.location.href = 'login.html';  // ไปหน้า login
        } else if (response.ok) {
            // alert('Transaction added successfully!');
            window.location.href = 'index.html'; // ไปหน้า index.html หลังจากเพิ่มรายการสำเร็จ
        } else {
            alert('Error: ' + data.message);
            console.error('Error data:', data);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred. Please try again later.');
    }
});
