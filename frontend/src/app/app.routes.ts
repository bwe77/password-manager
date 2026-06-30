import { Routes } from '@angular/router';
import { DashboardComponent } from './components/dashboard/dashboard';
import { LoginComponent } from './components/auth/login/login.component';
import { RegisterComponent } from './components/auth/register/register.component';

/**
 * Application Routes
 * 
 * Route Structure:
 * - / → Redirect to /dashboard
 * - /login → Login page
 * - /register → Registration page
 * - /dashboard → Security dashboard (protected)
 * - ** → Redirect to dashboard
 */
export const routes: Routes = [
  // Default route - redirect to dashboard
  {
    path: '',
    redirectTo: '/dashboard',
    pathMatch: 'full'
  },

  // Auth routes
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'register',
    component: RegisterComponent
  },

  // Dashboard route (will be protected with AuthGuard later)
  {
    path: 'dashboard',
    component: DashboardComponent,
    // TODO: Add AuthGuard
    // canActivate: [AuthGuard]
  },

  // 404 Fallback - redirect to dashboard
  {
    path: '**',
    redirectTo: '/dashboard'
  }
];