(() => {
  const root = document.getElementById('penumbra-studio');
  if (!root) return;
  const views = root.querySelectorAll('[data-view]');
  views.forEach(button => button.addEventListener('click', () => {
    const show = button.dataset.view;
    root.querySelector('.example-view').hidden = show !== 'example';
    root.querySelector('.reasoning-view').hidden = show !== 'reasoning';
    views.forEach(other => other.setAttribute('aria-pressed', String(other === button)));
  }));
})();
