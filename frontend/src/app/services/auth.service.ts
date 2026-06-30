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

            this.http.post()
        }
    }
    

    getUserFromStorage(): User | null {
        throw new Error("Method not implemented.");
    }
}