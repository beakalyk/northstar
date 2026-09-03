import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterOutlet } from '@angular/router';
import { HttpClient } from '@angular/common/http';

type Role = 'Administrator' | 'Manager' | 'Member';

interface RoleConfig {
  role: Role;
  initials: string;
  color: string;
  title: string;
  summary: string;
  tasks: number;
  action: string;
}

@Component({
  selector: 'app-root',
  imports: [CommonModule, FormsModule, RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  private readonly http = inject(HttpClient);
  // `/api` is proxied to Flask during development. Keeping requests same-origin
  // lets Angular's built-in XSRF interceptor attach the CSRF header safely.
  private readonly api = '/api';
  protected readonly isAuthenticated = signal(false);
  protected readonly selectedRole = signal<Role>('Manager');
  protected readonly email = signal('alex@northstar.io');
  protected readonly password = signal('');
  protected readonly showPassword = signal(false);
  protected readonly notice = signal('');
  protected readonly isLoading = signal(false);

  protected readonly roles: RoleConfig[] = [
    { role: 'Administrator', initials: 'AD', color: '#7657e8', title: 'Keep the organization moving.', summary: 'Manage people, workspace access, and the work that needs your attention.', tasks: 12, action: 'Review workspace' },
    { role: 'Manager', initials: 'MG', color: '#168b7a', title: 'Your team is making progress.', summary: 'See priorities, clear blockers, and keep the next milestone on track.', tasks: 8, action: 'Review team plan' },
    { role: 'Member', initials: 'MB', color: '#e67b44', title: 'Make meaningful progress today.', summary: 'Your focused workspace for assigned work, updates, and next steps.', tasks: 5, action: 'Open my tasks' }
  ];

  protected readonly current = computed(() => this.roles.find((item) => item.role === this.selectedRole())!);
  protected readonly firstName = computed(() => this.email().split('@')[0].split(/[._-]/)[0].replace(/^./, (letter) => letter.toUpperCase()) || 'Alex');

  constructor() {
    this.http.get(`${this.api}/auth/csrf`, { withCredentials: true }).subscribe({
      next: () => this.restoreSession(),
      error: () => this.notice.set('Authentication service is unavailable. Start the Flask API to sign in.')
    });
  }

  protected selectRole(role: Role): void { this.selectedRole.set(role); this.notice.set(''); }
  protected signIn(): void {
    if (!this.email().includes('@') || this.password().length < 4) {
      this.notice.set('Enter a valid email and a password of at least 4 characters.'); return;
    }
    this.isLoading.set(true); this.notice.set('');
    this.http.post<{ user: { email: string; firstName: string; role: Role } }>(`${this.api}/auth/login`, { email: this.email(), password: this.password() }, { withCredentials: true }).subscribe({
      next: ({ user }) => {
        this.email.set(user.email); this.selectedRole.set(user.role); this.isAuthenticated.set(true); this.password.set(''); this.isLoading.set(false);
      },
      error: (error) => { this.notice.set(error?.error?.error || 'Unable to sign in. Try again.'); this.isLoading.set(false); }
    });
  }
  protected demoSignIn(role: Role): void { this.selectRole(role); this.email.set(`${role.toLowerCase()}@northstar.io`); this.password.set('ChangeMe123!'); this.signIn(); }
  protected signOut(): void {
    this.http.post(`${this.api}/auth/logout`, {}, { withCredentials: true }).subscribe({ complete: () => { this.isAuthenticated.set(false); this.password.set(''); } });
  }
  protected say(message: string): void { this.notice.set(message); window.setTimeout(() => this.notice.set(''), 2600); }

  private restoreSession(): void {
    this.http.get<{ user: { email: string; role: Role } }>(`${this.api}/auth/me`, { withCredentials: true }).subscribe({
      next: ({ user }) => { this.email.set(user.email); this.selectedRole.set(user.role); this.isAuthenticated.set(true); }
    });
  }
}
