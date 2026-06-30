import { Injectable } from "@angular/core";
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { Router } from '@angular/router';
import { environment } from '../../environments/environment';
import { response } from "express";

//interfaces
export interface LoginRequest{
    email: string;
    masterPassword: string;
    totpCode?: string;
}

export interface RegisterRequest{
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

/**
 * Authentication Service
 * 
 * Handles:
 * - User registration
 * - User login/logout
 * - Token management
 * - Current user state
 */
@Injectable({
    providedIn: 'root'
})
export class AuthService {
    private apiUrl = environment.apiUrl;

    // Current user state 
    private currentUserSubject = new BehaviorSubject<User | null>(this.getUserFromStorage());
    public currentUser$ = this.currentUserSubject.asObservable();

    //is user logged in
    private isAuthenticatedSubject = new BehaviorSubject<boolean>(this.hasValidToken());
    public isAuthenticcated$ = this.isAuthenticatedSubject.asObservable();

    constructor(
        private http: HttpClient,
        private router: Router
    ){
        //check token validity on service initialisation
        this.checkTokenValidity();
    }

    /**
   * Register a new user
   */
    register(request: RegisterRequest): Observable<AuthResponse>{
        return this.http.post<AuthResponse>(`${this.apiUrl}/auth/register`, request)
            .pipe(
                tap(response => this.handleAuthResponse(response))
            );
    }

     /**
   * Login existing user
   */
    login(request: LoginRequest): Observable<AuthResponse>{
        return this.http.post<AuthResponse>(`${this.apiUrl}/auth/login`, request)
            .pipe(
                tap(response => this.handleAuthResponse(response))
            );
    } 

    /**
     * logout current user
     */
    logout(): void{
        const refreshToken = this.getRefreshToken();

        if(refreshToken){
            // call logout endpoint 
            const headers = new HttpHeaders({
                'Authorization': `Bearer ${refreshToken}`
            });

            this.http.post(`${this.apiUrl}/auth/logout`, {}, { headers })
                .subscribe({
                    next: () => console.log('Logout successful'),
                    error: (err) => console.error('Logout failed', err)
                });
        }

        //clear local storage
        this.clearAuthData();

        //update observables
        this.currentUserSubject.next(null);
        this.isAuthenticatedSubject.next(false);

        //redirect to login
        this.router.navigate(['/login']);
    }

    // refresh access token
    refreshToken(): Observable<AuthResponse> {
        const refreshToken = this.getRefreshToken();

        if(!refreshToken){
            throw new Error("No refresh token available");
        }

        const headers = new HttpHeaders({
            'Authorization': `Bearer ${refreshToken}`
        });

        return this.http.post<AuthResponse>(`${this.apiUrl}/auth/refresh`, {}, { headers })
            .pipe(
                tap(response => this.handleAuthResponse(response))
            );
    }

    // Get current access token
    getAccessToken(): string | null{
        return localStorage.getItem('accessToken');
    }


    private clearAuthData(): void {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
    }


    getRefreshToken() {
        return localStorage.getItem('refreshToken');
    }
    

    getCurrentUser(): User | null {
        return this.currentUserSubject.value;
    }

    isAuthenticated(): boolean {
        return this.isAuthenticatedSubject.value;
    }

    private handleAuthResponse(response: AuthResponse): void {
        //store tokens
        localStorage.setItem('accessToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);

        //store user info
        const user: User = {
            userId: response.userId,
            email: response.email,
            totpEnabled: response.totpEnabled
        };
        localStorage.setItem('user', JSON.stringify(user));

        //update observables
        this.currentUserSubject.next(user);
        this.isAuthenticatedSubject.next(true);
    }

    private getUserFromStorage(): User | null {
        const userJson = localStorage.getItem('user');
        if (!userJson) {
            return null;
        }

        try {
            return JSON.parse(userJson) as User;
        } catch {
            return null;
        }
    }

    private hasValidToken(): boolean {
        const token = this.getAccessToken();
        if(!token) return false;

        try{
            const payload = this.parseJwt(token);
            const now = Date.now() / 1000;
            return payload.exp > now;

        } catch{
            return false;
        }
    }

    private parseJwt(token: string): any {
        try{
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));

            return JSON.parse(jsonPayload);
        } catch{
            return null;
        }
    }

    private checkTokenValidity(): void {
    if (!this.hasValidToken()) {
        this.clearAuthData();
        this.isAuthenticatedSubject.next(false);
        this.currentUserSubject.next(null);
        }
    }
    
}
