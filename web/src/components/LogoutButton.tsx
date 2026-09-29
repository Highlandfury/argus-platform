"use client";

import { readCSRF } from "@/lib/api";

export default function LogoutButton() {
  async function logout() {
    await fetch("/api/v1/auth/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": readCSRF() },
    });
    window.location.href = "/login";
  }

  return (
    <button className="logout" onClick={logout} data-testid="logout">
      Sign out
    </button>
  );
}
