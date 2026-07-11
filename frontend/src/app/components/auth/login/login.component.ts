import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../../services/auth.service';
import { form } from '@angular/forms/signals';

@Component({
    selector: 'app-login',
    standalone: true,
    imports: [CommonModule, ReactiveFormsModule, RouterLink],
    templateUrl: './login.component.html',
    styleUrl: './login.component.scss',
})
export class LoginComponent {
    loginForm: FormGroup;
    loading = false;
    error: string | null = null;
    showPassword = false;

    constructor(
        private fb: FormBuilder,
        private authService: AuthService,
        private router: Router
    ) {
        this.loginForm = this.fb.group({
            email: ['', [Validators.required, Validators.email]],
            masterPassword: ['', [Validators.required, Validators.minLength(6)]],
        });
    }

    /**
     * Toggle password visibility
     */
    togglePasswordVisibility(): void {
        this.showPassword = !this.showPassword;
    }

    /**
     * Handle form submission for login
     */
    onSubmit(): void {
        this.error = null;

        if (this.loginForm.invalid) {
            this.markFormGroupToched(this.loginForm);
            return;
        }

        this.loading = true;

        const credentials = this.loginForm.value;

        this.authService.login(credentials).subscribe({
            next: (response: any) => {
                console.log('Login successful', response);
                this.loading = false;

                // Navigate to dashboard or home page after successful login
                this.router.navigate(['/dashboard']);
            },
            error: (err: { status: number; error: { message: string; }; }) => {
                this.loading = false;

                if (err.status === 401) {
                    this.error = 'Invalid email or password. Please try again.';
                } else if (err.status === 403) {
                    this.error = '2FA required. Please complete the verification process.';
                } else if (err.status === 0) {
                    this.error = 'Cannot connect to the server. Please check your internet connection.';
                } else {
                    this.error = err.error?.message || 'Login failed. Please try again.';
                }
            }
        });
    }

    /**
     * Mark all controls in a form group as touched to trigger validation messages
     * @param formGroup The form group to mark
     */
    private markFormGroupToched(formGroup: FormGroup): void {
        Object.keys(formGroup.controls).forEach((key) => {
            const control = formGroup.get(key);
            control?.markAsTouched();
        });
    }

    /**
     * Check if form field has an error
    */
    hasError(fieldName: string, errorType: string): boolean {
        const field = this.loginForm.get(fieldName);
        return !!(field?.hasError(errorType) && field?.touched);
    }

}




