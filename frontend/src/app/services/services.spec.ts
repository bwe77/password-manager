import { TestBed } from '@angular/core/testing';

import { Servies } from './servies';

describe('Servies', () => {
  let service: Servies;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(Servies);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
