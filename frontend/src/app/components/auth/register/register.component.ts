import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule, AbstractControl, ValidationErrors } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../../services/auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl:'./register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent {
    registerForm: FormGroup;
    loading = false;
    error: string | null = null;
    showPassword = false;
    showConfirmPassword = false;
    passwordStrength = 0;

    constructor(
        private formBuilder: FormBuilder,
        private authService: AuthService,
        private router: Router
    ) {
        this.registerForm = this.formBuilder.group({
            email: ['', [Validators.required, Validators.email]],
            masterPassword: ['', [
                Validators.required,
                Validators.minLength(12),
                this.passwordStrengthValidator
            ]],
            masterPasswordConfirm: ['', [Validators.required]]
        }, {
            validators: this.passwordMatchValidator
        });

        // watch password changes for stremgth indicator
        this.registerForm.get('masterPassword')?.valueChanges.subscribe(password => {
            this.passwordStrength = this.calculatePasswordStrength(password);
        });
    }

    passwordStrengthValidator(control: AbstractControl): ValidationErrors | null {
        const password = control.value;
        if(!password) return null;

        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumeric = /[0-9]/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        const valid = hasUpperCase && hasLowerCase && hasNumeric && hasSpecial;
        return valid ? null : {weakPassword: true};
    }

    passwordMatchValidator(group: AbstractControl): ValidationErrors | null {
        const password = group.get('masterPassword')?.value;
        const confirm = group.get('masterPasswordConfirm')?.value;
        return password === confirm ? null : {passwordMismatch: true};
    }

    calculatePasswordStrength(password: string): number {
        if (!password) return 0;

        let strength = 0;
        
        // Length score
        if (password.length >= 12) strength += 25;
        if (password.length >= 16) strength += 25;

        // Character variety
        if (/[a-z]/.test(password)) strength += 12.5;
        if (/[A-Z]/.test(password)) strength += 12.5;
        if (/\d/.test(password)) strength += 12.5;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength += 12.5;

        return Math.min(100, strength);
    }

    getStrengthLabel(): string {
        if (this.passwordStrength >= 95) return 'Very Strong';
        if (this.passwordStrength >= 75) return 'Strong';
        if (this.passwordStrength >= 50) return 'Moderate';
        if (this.passwordStrength >= 25) return 'Weak';
        return 'Very Weak';
    }

    getStrengthColor(): string {
        if (this.passwordStrength >= 95) return '#10e77f';
        if (this.passwordStrength >= 75) return '#10b981';
        if (this.passwordStrength >= 50) return '#f59e0b';
        if (this.passwordStrength >= 25) return '#ef4444';

        return '#ef4444';
    }

    togglePasswordVisibility(field: 'password' | 'confirm'): void {
        if (field === 'password') {
        this.showPassword = !this.showPassword;
        } else {
        this.showConfirmPassword = !this.showConfirmPassword;
        }
    }

    onSubmit(): void {
        this.error = null;

        if(this.registerForm.invalid){
            this.markFormGroupTouched(this.registerForm);
            return;
        }

        this.loading = true;

        const { email, masterPassword, masterPasswordConfirm } = this.registerForm.value;

         this.authService.register({ email, masterPassword, masterPasswordConfirm }).subscribe({
            next: (response: any) => {
                console.log('Registration successful', response);
                this.loading = false;

                // Navigate to dashboard or home page after successful registration
                this.router.navigate(['/dashboard']);
            },
            error: (err: { status: number; error: { message: string; }; }) => {
                console.error('Registration error', err);
                this.loading = false;

                if (err.status === 401) {
                    this.error = 'Invalid email or password. Please try again.';
                } else if (err.status === 403) {
                    this.error = '2FA required. Please complete the verification process.';
                } else if (err.status === 0) {
                    this.error = 'Cannot connect to the server. Please check your internet connection.';
                } else {
                    this.error = err.error?.message || 'Registration failed. Please try again.';
                }
            }
        });
    }

    private markFormGroupTouched(formGroup: FormGroup): void {
        Object.keys(formGroup.controls).forEach(key => {
            const control = formGroup.get(key);
            control?.markAsTouched();
        });
    }

    get passwordValue(): string {
        return this.registerForm.get('masterPassword')?.value || '';
    }

    hasMinLength(): boolean   { return this.passwordValue.length >= 12; }
    hasUpperCase(): boolean   { return /[A-Z]/.test(this.passwordValue); }
    hasLowerCase(): boolean   { return /[a-z]/.test(this.passwordValue); }
    hasNumber(): boolean      { return /\d/.test(this.passwordValue); }
    hasSpecialChar(): boolean { return /[!@#$%^&*(),.?":{}|<>]/.test(this.passwordValue); }

    
    hasError(fieldName: string, errorType: string): boolean {
        const field = this.registerForm.get(fieldName);
        return !!(field?.hasError(errorType) && field?.touched);
    }

    /**
     * Check if form has error
     */
    hasFormError(errorType: string): boolean {
        return !!(this.registerForm.hasError(errorType) && this.registerForm.touched);
    }
}