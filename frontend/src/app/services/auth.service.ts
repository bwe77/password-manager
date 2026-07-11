import { Injectable, PLATFORM_ID, inject } from "@angular/core";
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { isPlatformBrowser } from '@angular/common';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { Router } from '@angular/router';
import { environment } from '../../environments/environment';

// --- Interfaces ---
export interface LoginRequest {
  email: string;
  masterPassword: string;
  totpCode?: string;
}

export interface RegisterRequest {
  email: string;
  masterPassword: string;
  masterPasswordConfirm: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  userId: number;
  email: string;
  totpEnabled: boolean;
}

export interface User {
  userId: number;
  email: string;
  totpEnabled: boolean;
}

// --- Storage keys (centralized so you never typo them) ---
const ACCESS_TOKEN_KEY = 'accessToken';
const REFRESH_TOKEN_KEY = 'refreshToken';
const USER_KEY = 'currentUser';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = environment.apiUrl;
  private platformId = inject(PLATFORM_ID);

  private currentUserSubject = new BehaviorSubject<User | null>(this.getUserFromStorage());
  public currentUser$ = this.currentUserSubject.asObservable();

  private isAuthenticatedSubject = new BehaviorSubject<boolean>(this.hasValidToken());
  public isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  constructor(
    private http: HttpClient,
    private router: Router
  ) {
    this.checkTokenValidity();
  }

  private get isBrowser(): boolean {
    return isPlatformBrowser(this.platformId);
  }

  // --- Public API ---

  register(request: RegisterRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/auth/register`, request)
      .pipe(tap(response => this.handleAuthResponse(response)));
  }

  login(request: LoginRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/auth/login`, request)
      .pipe(tap(response => this.handleAuthResponse(response)));
  }

  logout(): void {
    const refreshToken = this.getRefreshToken();

    // Clear local state immediately so the UI updates even if the
    // network call fails. The token is being discarded either way.
    this.clearStorage();
    this.currentUserSubject.next(null);
    this.isAuthenticatedSubject.next(false);

    if (refreshToken) {
      const headers = new HttpHeaders({
        Authorization: `Bearer ${refreshToken}`
      });

      // Backend returns 204 No Content. We don't block navigation on it —
      // best-effort revocation of the refresh token server-side.
      this.http.post<void>(`${this.apiUrl}/auth/logout`, {}, { headers })
        .subscribe({
          next: () => {},
          error: (err) => console.error('Logout request failed', err)
        });
    }

    this.router.navigate(['/login']);
  }

  isAuthenticated(): boolean {
    return this.hasValidToken();
  }

  getToken(): string | null {
    if (!this.isBrowser) return null;
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  }

  getRefreshToken(): string | null {
    if (!this.isBrowser) return null;
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  }

  // --- Private helpers ---

  private handleAuthResponse(response: AuthResponse): void {
    if (this.isBrowser) {
      localStorage.setItem(ACCESS_TOKEN_KEY, response.accessToken);
      localStorage.setItem(REFRESH_TOKEN_KEY, response.refreshToken);
      localStorage.setItem(USER_KEY, JSON.stringify({
        userId: response.userId,
        email: response.email,
        totpEnabled: response.totpEnabled
      }));
    }

    const user: User = {
      userId: response.userId,
      email: response.email,
      totpEnabled: response.totpEnabled
    };
    this.currentUserSubject.next(user);
    this.isAuthenticatedSubject.next(true);
  }

  getUserFromStorage(): User | null {
    if (!this.isBrowser) return null;
    const raw = localStorage.getItem(USER_KEY);
    try {
      return raw ? JSON.parse(raw) as User : null;
    } catch {
      return null;
    }
  }

  private hasValidToken(): boolean {
    const token = this.getToken();
    if (!token) return false;

    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const expiryMs = payload.exp * 1000; // JWT `exp` is in seconds
      return Date.now() < expiryMs;
    } catch {
      return false; // malformed token
    }
  }

  private checkTokenValidity(): void {
    if (this.hasValidToken()) {
      this.isAuthenticatedSubject.next(true);
    } else {
      // Token missing or expired — make sure stale state is wiped.
      this.clearStorage();
      this.currentUserSubject.next(null);
      this.isAuthenticatedSubject.next(false);
    }
  }

  private clearStorage(): void {
    if (!this.isBrowser) return;
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }
}