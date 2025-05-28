document.getElementById('back-btn').addEventListener('click', () => {
    window.location.href = 'main.html';  // กลับไปที่หน้ารายการธุรกรรม
});

// ดึงข้อมูลสำหรับกราฟ
const fetchChartData = async () => {
    const token = localStorage.getItem('token');

    if (!token) {
        alert('Token is missing. Please log in again.');
        window.location.href = 'login.html';
        return;
    }

    try {
        const response = await fetch('http://localhost:3001/api/chart-data', {
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

        const chartData = await response.json();
        renderChart(chartData); // แสดงกราฟด้วยข้อมูลที่ดึงมา
    } catch (error) {
        console.error('Error fetching chart data:', error);
        alert('An error occurred while fetching chart data.');
    }
};

// ฟังก์ชันแสดงกราฟ
const renderChart = (chartData) => {
    const ctx = document.getElementById('expenseChart').getContext('2d');
    // eslint-disable-next-line no-undef
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: chartData.labels,
            datasets: [{
                label: 'Expenses by Category',
                data: chartData.data,
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
};

document.getElementById('back-btn').addEventListener('click', () => {
    window.location.href = 'index.html';
});



// เรียกใช้ฟังก์ชันดึงข้อมูลเมื่อหน้าโหลด
window.onload = fetchChartData;
