// Minimal read-only SPA for Lore. Talks to the BFF's JSON API under /api and
// the OIDC endpoints under /auth. No build step.
const app = document.getElementById("app");
const userEl = document.getElementById("user");

function escapeHtml(s) {
  return (s || "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

function showLogin() {
  userEl.textContent = "";
  const failed = new URLSearchParams(location.search).get("login") === "failed";
  app.innerHTML = `
    ${failed ? '<p class="error">Login failed. Please try again.</p>' : ""}
    <p>Sign in to browse the repositories you can access.</p>
    <p><a class="btn" href="/auth/login">Sign in with Dex</a></p>`;
}

async function showRepos() {
  app.innerHTML = '<h2>Repositories</h2><p class="muted">Loading…</p>';
  const r = await fetch("/api/repos");
  if (!r.ok) {
    app.innerHTML = '<h2>Repositories</h2><p class="error">Could not load repositories.</p>';
    return;
  }
  const repos = await r.json();
  if (!repos.length) {
    app.innerHTML =
      '<h2>Repositories</h2><p class="muted">You have access to no repositories yet.</p>';
    return;
  }
  const rows = repos
    .map(
      (repo) => `
      <li>
        <div class="name">${escapeHtml(repo.name)}</div>
        ${repo.description ? `<div class="desc">${escapeHtml(repo.description)}</div>` : ""}
        <div class="meta">${escapeHtml(repo.id)}${
          repo.default_branch ? ` · ${escapeHtml(repo.default_branch)}` : ""
        }</div>
      </li>`,
    )
    .join("");
  app.innerHTML = `<h2>Repositories</h2><ul class="repos">${rows}</ul>`;
}

async function init() {
  const me = await fetch("/api/me");
  if (me.status === 401) {
    showLogin();
    return;
  }
  if (!me.ok) {
    app.innerHTML = '<p class="error">Something went wrong.</p>';
    return;
  }
  const u = await me.json();
  userEl.innerHTML = `${escapeHtml(u.user_name || u.sub)} · <a href="/auth/logout">Sign out</a>`;
  await showRepos();
}

init();
