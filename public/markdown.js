// Tiny markdown renderer for question text + descriptions.
// Supports: **bold**, *italic*, `code`, [link](url), line breaks.
// All HTML is escaped first; only the recognised patterns are inserted as tags.
(function () {
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c];
    });
  }
  function safeUrl(u) {
    var trimmed = String(u || '').trim();
    if (/^javascript:/i.test(trimmed)) return '#';
    if (!/^(https?:\/\/|mailto:|\/)/.test(trimmed)) return '#';
    return trimmed.replace(/"/g, '&quot;');
  }
  window.renderMarkdown = function (input) {
    var html = escapeHtml(input || '');
    // links first (so ** inside link text still works in the next step)
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (_, t, u) {
      return '<a href="' + safeUrl(u) + '" target="_blank" rel="noopener">' + t + '</a>';
    });
    html = html.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    html = html.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    html = html.replace(/\n/g, '<br>');
    return html;
  };
  // Convenience: set element's innerHTML from a markdown string
  window.setMarkdown = function (el, input) {
    if (!el) return;
    el.innerHTML = window.renderMarkdown(input);
  };
})();
