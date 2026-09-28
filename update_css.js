const fs = require('fs');
let css = fs.readFileSync('public/style.css', 'utf8');

// Remove the gradient on body
css = css.replace(/background-image:\s*radial-gradient[^;]+;/g, '');

// Flatten background colors to slate and solid
css = css.replace(/--bg-primary:\s*[^;]+;/g, '--bg-primary: #0f172a;');
css = css.replace(/--bg-secondary:\s*[^;]+;/g, '--bg-secondary: #1e293b;');
css = css.replace(/--bg-tertiary:\s*[^;]+;/g, '--bg-tertiary: #334155;');
css = css.replace(/--border-subtle:\s*[^;]+;/g, '--border-subtle: #334155;');

css += `
/* Modern Selects & Kick Button */
.modern-select {
  width: 100%;
  padding: 10px 12px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  font-family: var(--font-sans);
  font-size: 0.9rem;
}
.modern-select:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.form-group label {
  display: block;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 4px;
}
.kick-btn {
  background: none;
  border: none;
  color: var(--error-red);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2px;
  border-radius: 4px;
  margin-left: auto;
}
.kick-btn:hover {
  background: rgba(244, 63, 94, 0.1);
}
.player-badge {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  width: 100%;
}
.selector-container {
  background: var(--bg-secondary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}
`;

fs.writeFileSync('public/style.css', css);
console.log('style.css updated for flat design & components');
