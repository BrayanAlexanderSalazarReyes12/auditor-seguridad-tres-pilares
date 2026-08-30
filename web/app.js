"use strict";

const token = document.querySelector('meta[name="auditor-token"]').content;
const pageTitles = {
  audit: "Auditoría de los tres pilares",
  results: "Evidencia y hallazgos",
  manual: "Manual operativo integrado",
};
let lastStatus = "idle";
let toastTimer = null;
let shuttingDown = false;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const MAX_IDENTITIES = 12;

function identityLabel(index) {
  return String.fromCharCode("A".charCodeAt(0) + index);
}

function refreshIdentityCards() {
  $$("[data-identity-card]").forEach((card, index) => {
    const label = identityLabel(index);
    card.dataset.label = label;
    card.querySelector(".identity-letter").textContent = label;
    card.querySelector(".identity-name").textContent = `Usuario ${label}`;
    const username = card.querySelector(".identity-username");
    const password = card.querySelector(".identity-password");
    username.id = `identity-username-${label}`;
    password.id = `identity-password-${label}`;
    card.querySelector(".username-label").htmlFor = username.id;
    card.querySelector(".password-label").htmlFor = password.id;
    const remove = card.querySelector(".remove-identity");
    remove.hidden = index === 0;
  });
}

function addIdentityCard() {
  const list = $("#identities-list");
  const index = list.children.length;
  if (index >= MAX_IDENTITIES) return showToast("Se permiten máximo 12 identidades (A–L).", true);
  const card = document.createElement("section");
  card.className = "identity-card identity-simple";
  card.dataset.identityCard = "";

  const title = document.createElement("div");
  title.className = "identity-title";
  const letter = document.createElement("span");
  letter.className = "identity-letter";
  const titleText = document.createElement("div");
  const name = document.createElement("strong");
  name.className = "identity-name";
  const hint = document.createElement("small");
  hint.textContent = "Credencial ficticia del laboratorio";
  titleText.append(name, hint);
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "remove-identity";
  remove.textContent = "Eliminar";
  remove.addEventListener("click", () => {
    card.remove();
    refreshIdentityCards();
  });
  title.append(letter, titleText, remove);

  const fields = document.createElement("div");
  fields.className = "two-cols";
  const usernameField = document.createElement("div");
  usernameField.className = "field";
  const usernameLabel = document.createElement("label");
  usernameLabel.className = "username-label";
  usernameLabel.textContent = "Nombre de usuario";
  const username = document.createElement("input");
  username.className = "identity-username";
  username.autocomplete = "off";
  username.placeholder = "usuario.laboratorio";
  usernameField.append(usernameLabel, username);
  const passwordField = document.createElement("div");
  passwordField.className = "field";
  const passwordLabel = document.createElement("label");
  passwordLabel.className = "password-label";
  passwordLabel.textContent = "Contraseña";
  const password = document.createElement("input");
  password.className = "identity-password";
  password.type = "password";
  password.autocomplete = "new-password";
  passwordField.append(passwordLabel, password);
  fields.append(usernameField, passwordField);
  card.append(title, fields);
  list.appendChild(card);
  refreshIdentityCards();
  if (index > 0) username.focus();
}

function collectIdentities() {
  return $$("[data-identity-card]").map((card, index) => ({
    label: identityLabel(index),
    username: card.querySelector(".identity-username").value,
    password: card.querySelector(".identity-password").value,
  }));
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast show${error ? " error" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.className = "toast"; }, 4200);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Auditor-Token": token,
      ...(options.headers || {}),
    },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Error HTTP ${response.status}`);
  return data;
}

function navigate(name) {
  $$(".page").forEach((page) => page.classList.remove("active"));
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.page === name));
  $(`#page-${name}`).classList.add("active");
  $("#page-title").textContent = pageTitles[name];
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setStatus(state) {
  const pill = $("#status-pill");
  pill.className = `status-pill ${state.status || "idle"}`;
  pill.querySelector("span").textContent = state.message || "Listo";
  const running = state.status === "running";
  $("#progress").classList.toggle("running", running);
  $("#run-indicator").textContent = running ? "Ejecutando" : state.status === "complete" ? "Finalizado" : state.status === "error" ? "Requiere atención" : "En espera";
  $("#run-button").disabled = running;
  $("#cancel-button").disabled = !running;
}

function badge(text, kind) {
  const span = document.createElement("span");
  span.className = `badge ${String(kind || "").toLowerCase()}`;
  span.textContent = text;
  return span;
}

function renderSummary(summary) {
  if (!summary) return;
  $("#metric-findings").textContent = summary.findings;
  $("#metric-confirmed").textContent = summary.confirmed;
  $("#metric-critical").textContent = summary.critical;
  $("#metric-high").textContent = summary.high;
  const tbody = $("#findings-body");
  tbody.replaceChildren();
  if (!summary.items.length) {
    const row = document.createElement("tr");
    row.className = "empty";
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "La corrida no promovió hallazgos dentro del alcance ejecutado.";
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }
  summary.items.forEach((finding) => {
    const row = document.createElement("tr");
    const values = [finding.regla_id || "SIN-REGLA", finding.pilar ?? "?", null, null, finding.hallazgo || "Hallazgo sin título"];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      if (index === 2) cell.appendChild(badge(finding.severidad || "INFORMATIVA", finding.severidad));
      else if (index === 3) cell.appendChild(badge(finding.estado_final || "REQUIERE_REVISION", finding.estado_final));
      else cell.textContent = String(value);
      row.appendChild(cell);
    });
    tbody.appendChild(row);
  });
}

async function pollStatus() {
  try {
    const state = await api("/api/status", { method: "GET" });
    setStatus(state);
    if (state.logs && state.logs.length) {
      const consoleBox = $("#console");
      const next = state.logs.join("\n");
      if (consoleBox.textContent !== next) {
        consoleBox.textContent = next;
        consoleBox.scrollTop = consoleBox.scrollHeight;
      }
    }
    if (state.summary) renderSummary(state.summary);
    if (lastStatus === "running" && state.status === "complete") {
      navigate("results");
      showToast(state.message || "Auditoría finalizada");
    }
    if (lastStatus === "running" && state.status === "error") showToast(state.message || "La auditoría requiere atención", true);
    lastStatus = state.status;
  } catch (error) {
    setStatus({ status: "error", message: "Interfaz desconectada" });
  } finally {
    if (!shuttingDown) setTimeout(pollStatus, 900);
  }
}

$$('.nav-item').forEach((button) => button.addEventListener("click", () => navigate(button.dataset.page)));

$("#add-identity").addEventListener("click", addIdentityCard);
addIdentityCard();

$$('[data-select]').forEach((button) => button.addEventListener("click", async () => {
  const kind = button.dataset.select;
  const defaultTargets = { repository: "repository", config: "config", output: "output_dir", comparison: "compare_with" };
  const target = button.dataset.target || defaultTargets[kind];
  const oldText = button.textContent;
  button.disabled = true;
  button.textContent = "Abriendo…";
  try {
    const targetInput = document.getElementById(target);
    const result = await api("/api/select", {
      method: "POST",
      body: JSON.stringify({ kind, current: targetInput ? targetInput.value : "" }),
    });
    if (result.path && targetInput) {
      targetInput.value = result.path;
      targetInput.dispatchEvent(new Event("change", { bubbles: true }));
      showToast("Ruta seleccionada correctamente.");
    } else {
      showToast("Selección cancelada. También puede escribir la ruta manualmente.");
    }
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = oldText;
  }
}));

$("#audit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const pillars = $$('input[name="pillar"]:checked').map((item) => Number(item.value));
  if (!pillars.length) return showToast("Seleccione al menos un pilar.", true);
  if (!$("#authorized").checked) return showToast("Debe confirmar la autorización expresa.", true);
  if ($("#active_tests").checked && !window.confirm("Se ejecutarán solicitudes activas acotadas. ¿Confirma que el laboratorio es autorizado y desechable?")) return;
  if ($("#allow_network").checked && !window.confirm("La URL no local debe estar incluida expresamente en el alcance. ¿Desea continuar?")) return;
  const condition = $('input[name="condition"]:checked').value;
  const payload = {
    repository: $("#repository").value.trim(),
    config: $("#config").value.trim(),
    output_dir: $("#output_dir").value.trim(),
    base_url: $("#base_url").value.trim(),
    compare_with: $("#compare_with").value.trim(),
    fail_on: $("#fail_on").value,
    pillars,
    condition,
    generate_docx: $("#generate_docx").checked,
    active_tests: $("#active_tests").checked,
    allow_network: $("#allow_network").checked,
    authorized: $("#authorized").checked,
    identities: collectIdentities(),
  };
  try {
    await api("/api/run", { method: "POST", body: JSON.stringify(payload) });
    $$(".identity-password").forEach((input) => { input.value = ""; });
    $("#console").textContent = "Iniciando auditoría…";
    showToast("Auditoría iniciada. Las credenciales se retiraron del formulario.");
  } catch (error) {
    showToast(error.message, true);
  }
});

$("#cancel-button").addEventListener("click", async () => {
  if (!window.confirm("¿Desea cancelar la auditoría en curso?")) return;
  try {
    await api("/api/cancel", { method: "POST", body: "{}" });
    showToast("Cancelación solicitada.");
  } catch (error) { showToast(error.message, true); }
});

$("#load-evidence").addEventListener("click", async () => {
  const path = $("#evidence_path").value.trim();
  if (!path) return showToast("Seleccione una evidencia JSON.", true);
  try {
    const result = await api("/api/load-evidence", { method: "POST", body: JSON.stringify({ path }) });
    renderSummary(result.summary);
    showToast("Evidencia cargada correctamente.");
  } catch (error) { showToast(error.message, true); }
});

$$('[data-open]').forEach((button) => button.addEventListener("click", async () => {
  try {
    await api("/api/open", { method: "POST", body: JSON.stringify({ kind: button.dataset.open }) });
  } catch (error) { showToast(error.message, true); }
}));

$("#shutdown-button").addEventListener("click", async () => {
  if (!window.confirm("¿Desea cerrar la interfaz local? Una auditoría en curso será cancelada.")) return;
  try {
    const result = await api("/api/shutdown", { method: "POST", body: "{}" });
    shuttingDown = true;
    setStatus({ status: "idle", message: "Interfaz cerrada" });
    $("#shutdown-button").disabled = true;
    showToast(`${result.message} Ya puede cerrar esta pestaña.`);
  } catch (error) { showToast(error.message, true); }
});

pollStatus();
