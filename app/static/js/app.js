function showWelcome(name) {
  if (typeof Swal === 'undefined') {
    console.error('SweetAlert2 not loaded');
    return;
  }
  Swal.fire({
    title: 'Welcome!',
    text: `Hello, ${name}`,
    icon: 'success'
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('greet-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      const name = btn.dataset.username || 'there';
      showWelcome(name);
    });
  }
});
