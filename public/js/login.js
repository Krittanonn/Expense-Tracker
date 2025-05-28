document.getElementById('login-form').addEventListener('submit', async function(event) {
  event.preventDefault();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
      const response = await fetch('http://localhost:3001/api/login', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (data.token) {
          localStorage.setItem('token', data.token);

          window.location.href = 'index.html';
      } else {
          alert('Login failed: ' + data.message);
      }
  } catch (error) {
      console.error('Error logging in:', error);
      alert('Login failed, please try again.');
  }
});

document.getElementById('signup-btn').addEventListener('click', function() {
    window.location.href = 'signup.html'; 
  });
  