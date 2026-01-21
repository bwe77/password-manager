import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { environment } from '../../../environments/environment';
import { Router } from '@angular/router';

interface SecurityDashboard{
  totalPasswords: number;
  weakPasswords: number;
  breachedPasswords: number;
  reusedPasswords: number;
  expiredPasswords: number;
  overallSecurityScore: number;
  lastUpdated: string;
  recommendations: string[];
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})

export class DashboardComponent implements OnInit {
  dashboard: SecurityDashboard | null = null;
  loading = true;
  error: string | null = null;

  constructor(private http: HttpClient, private router: Router) {}
  
  ngOnInit(): void {
    this.loadDashboard();
  }

  loadDashboard(): void {
    const token = localStorage.getItem('accessToken');

    if(!token){
      this.router.navigate(['/login']);
      return;
    }

    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });

    this.http.get<SecurityDashboard>(`${environment.apiUrl}/dashboard`, { headers })
      .subscribe({
        next: (data) => {
          this.dashboard = data;
          this.loading = false;
        },
        error: (err) => {
          if (err.status === 401 || err.status === 403) {
            localStorage.removeItem('accessToken');
            this.router.navigate(['/login']);
            return;
          }
          this.error = 'Failed to load dashboard data.';
          this.loading = false;
          console.error('Dashboard error:', err);
        }
      });
  }

  getScoreColor(score: number): string{
      if (score >= 80) return '#10b981'; // green
      if (score >= 60) return '#f59e0b'; // yellow
      return '#ef4444'; // red
  }

  getScoreLabel(score: number): string{
      if (score >= 80) return 'Strong';
      if (score >= 60) return 'Moderate';
      if (score >= 40) return 'Fair';
      return 'Weak';
  }
}
