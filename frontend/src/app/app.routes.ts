import { Routes } from '@angular/router';
import { DashboardComponent } from './components/dashboard/dashboard';

/**
 * Application Routes
 * 
 * Route Structure:
 * - / → Redirect to /dashboard
 * - /dashboard → Show security dashboard
 * - /login → Login page (to be created)
 * - /register → Registration page (to be created)
 * - ** → 404 page (to be created)
 */
export const routes: Routes = [
    {
        path: '',
        redirectTo: '/dashboard',
        pathMatch: 'full'
    },
    {
        path: 'dashboard',
        component: DashboardComponent
        //TODO: add authGuards
        // canActivate: [AuthGuard]
    },

    // Auth routes (to be created)
    // {
    //   path: 'login',
    //   component: LoginComponent
    // },
    // {
    //   path: 'register',
    //   component: RegisterComponent
    // },

    // 404 Fallback

    {
        path: '**',
        redirectTo: '/dashboard'
    }
];