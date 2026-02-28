import {
  ref,
  query,
  limitToLast,
  onValue
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-database.js";

/* -------------------------------
   DOM
-------------------------------- */
const arpTable = document.getElementById("arpTable");
const ddosTable = document.getElementById("ddosTable");

const totalAlertsEl = document.getElementById("totalAlerts");
const arpCountEl = document.getElementById("arpCount");
const ddosCountEl = document.getElementById("ddosCount");
const blockedCountEl = document.getElementById("blockedCount");

/* -------------------------------
   STATE
-------------------------------- */
let arpCount = 0;
let ddosCount = 0;
let blockedCount = 0;

/* -------------------------------
   FIREBASE (LIMITED)
-------------------------------- */
const db = window.db;

const arpRef = query(
  ref(db, "netshield_logs/traffic/arp"),
  limitToLast(20)
);

const ddosRef = query(
  ref(db, "netshield_logs/traffic/ddos"),
  limitToLast(20)
);

/* -------------------------------
   HELPERS
-------------------------------- */
function safe(v) {
  return v === undefined || v === null ? "-" : v;
}

function updateTotals() {
  arpCountEl.innerText = arpCount;
  ddosCountEl.innerText = ddosCount;
  blockedCountEl.innerText = blockedCount;
  totalAlertsEl.innerText = arpCount + ddosCount;
}

/* -------------------------------
   ARP LISTENER
-------------------------------- */
onValue(arpRef, (snapshot) => {
  arpTable.innerHTML = "";
  arpCount = 0;

  if (!snapshot.exists()) {
    updateTotals();
    return;
  }

  const rows = Object.values(snapshot.val()).reverse();

  rows.forEach(d => {
    arpCount++;

    const high = d.severity === "HIGH";
    const severityClass = high ? "text-red-500 font-bold" : "text-green-400";

    arpTable.insertAdjacentHTML("beforeend", `
      <tr class="border-t border-gray-700 hover:bg-gray-700">
        <td class="p-2 text-sm text-gray-400">${safe(d.timestamp)}</td>
        <td class="p-2 font-mono text-blue-300">${safe(d.src_ip)}</td>
        <td class="p-2 font-mono text-gray-400">${safe(d.src_mac)}</td>
        <td class="p-2 font-mono text-blue-300">${safe(d.dst_ip)}</td>
        <td class="p-2 ${severityClass}">${safe(d.severity)}</td>
      </tr>
    `);
  });

  updateTotals();
});

/* -------------------------------
   DDOS LISTENER
-------------------------------- */
onValue(ddosRef, (snapshot) => {
  ddosTable.innerHTML = "";
  ddosCount = 0;
  blockedCount = 0;

  if (!snapshot.exists()) {
    updateTotals();
    return;
  }

  const rows = Object.values(snapshot.val()).reverse();

  rows.forEach(d => {
    ddosCount++;

    if (d.blocked === true || d.blocked === "true") {
      blockedCount++;
    }

    const high = d.severity === "HIGH";
    const severityClass = high ? "text-red-500 font-bold" : "text-green-400";

    ddosTable.insertAdjacentHTML("beforeend", `
      <tr class="border-t border-gray-700 hover:bg-gray-700">
        <td class="p-2 text-sm text-gray-400">${safe(d.timestamp)}</td>
        <td class="p-2 font-mono text-red-300">${safe(d.src_ip)}</td>
        <td class="p-2">${safe(d.syn)}</td>
        <td class="p-2">${safe(d.total)}</td>
        <td class="p-2 ${severityClass}">${safe(d.severity)}</td>
      </tr>
    `);
  });

  updateTotals();
});
