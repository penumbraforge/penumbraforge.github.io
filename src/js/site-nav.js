(() => {
  const header = document.getElementById('site-header');
  const toggle = header?.querySelector('.site-header-toggle');
  if (!toggle) return;
  document.documentElement.classList.add('has-site-menu');
  const setOpen = (open) => {
    header.classList.toggle('open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.innerHTML = open ? 'Close <span aria-hidden="true">−</span>' : 'Menu <span aria-hidden="true">+</span>';
  };
  toggle.addEventListener('click', () => setOpen(!header.classList.contains('open')));
  header.querySelectorAll('nav a').forEach(link => link.addEventListener('click', () => setOpen(false)));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && header.classList.contains('open')) {
      setOpen(false);
      toggle.focus();
    }
  });
  document.addEventListener('click', event => {
    if (!header.contains(event.target)) setOpen(false);
  });
  matchMedia('(min-width: 701px)').addEventListener('change', event => {
    if (event.matches) setOpen(false);
  });
})();
