const keyForInvite = (token: string) => `hubins:invite-email:${token}`;

export function saveInviteEmail(token: string, email: string): void {
  window.sessionStorage.setItem(keyForInvite(token), email);
}

export function loadInviteEmail(token: string): string {
  return window.sessionStorage.getItem(keyForInvite(token)) ?? '';
}
