document.getElementById('signup-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const data = {
        username: username,
        email: email,
        password: password
    };

    fetch('/api/register', { 
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === 'User registered successfully') {
            alert('Registration successful! Please log in.');
            window.location.href = '/'; // Redirect to login page (ใช้ / เพื่อให้ตรงกับเซิร์ฟเวอร์ที่ตั้งค่าไว้)
        } else {
            alert('Error: ' + data.message); // Show error message
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again later.');
    });
});
