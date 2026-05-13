(function () {
  function inject() {
    if (document.querySelector('.orb')) return;
    var frag = document.createDocumentFragment();
    for (var i = 1; i <= 3; i++) {
      var d = document.createElement('div');
      d.className = 'orb orb-' + i;
      d.setAttribute('aria-hidden', 'true');
      frag.appendChild(d);
    }
    document.body.insertBefore(frag, document.body.firstChild);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
