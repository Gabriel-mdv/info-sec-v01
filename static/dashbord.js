document.addEventListener('DOMContentLoaded', () => {
  // --- Smooth Scroll Navigation ---
  document.querySelectorAll('.sidebar-menu a').forEach(link => {
    link.addEventListener('click', e => {
      if (link.hash) {
        e.preventDefault();
        const section = document.querySelector(link.hash);
        if (section) {
          section.scrollIntoView({ behavior: 'smooth' });
        }
      }
    });
  });

  // --- Open/Close Modals ---
  document.querySelectorAll('[data-bs-toggle="modal"]').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = document.querySelector(btn.dataset.bsTarget);
      if (target) target.classList.add('active');
    });
  });
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', e => {
      if (e.target === modal) modal.classList.remove('active');
    });
  });

  // --- AJAX Create User ---
  const addUserForm = document.getElementById('add-user-form');
  if (addUserForm) {
    addUserForm.addEventListener('submit', async e => {
      e.preventDefault();
      const formData = new FormData(addUserForm);
      const response = await fetch(addUserForm.action, { method: 'POST', body: formData });
      if (response.ok) {
        alert('✅ User created successfully!');
        addUserForm.reset();
        document.querySelector('#addUserModal').classList.remove('active');
        window.location.reload();
      } else alert('❌ Failed to create user.');
    });
  }

  // --- AJAX File Upload ---
  const uploadForm = document.getElementById('upload-form');
  if (uploadForm) {
    uploadForm.addEventListener('submit', async e => {
      e.preventDefault();
      const formData = new FormData(uploadForm);
      const response = await fetch(uploadForm.action, { method: 'POST', body: formData });
      if (response.ok) {
        alert('✅ File uploaded successfully!');
        uploadForm.reset();
        window.location.reload();
      } else alert('❌ File upload failed.');
    });
  }
});
