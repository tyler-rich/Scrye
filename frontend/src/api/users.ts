/** API types and calls for admin user management. */

import { api, apiList } from './client';
import type { Role, UserInfo } from './auth';

export interface UserCreate {
  username: string;
  password: string;
  role: Role;
}

export interface UserUpdate {
  role?: Role;
  is_active?: boolean;
  password?: string;
}

export const listUsers = () => apiList<UserInfo>('/api/users');
export const createUser = (body: UserCreate) =>
  api<UserInfo>('/api/users', { method: 'POST', body });
export const updateUser = (id: number, body: UserUpdate) =>
  api<UserInfo>(`/api/users/${id}`, { method: 'PATCH', body });
