import { defineStore } from "pinia";
import { useLocalStorage } from "@vueuse/core";
import axios from "axios";

const apiUrl = "http://gastrozoom.studenti.sumit.ba/auth";

export const useAuthStore = defineStore("auth", {
  state: () => ({
    auth: useLocalStorage("auth", {
      token: "",
      isAutenticated: false,
      role: "",
    }),
    user: {},
  }),

  actions: {
    async register(credentials) {
      try {
        const res = await axios.post(`${apiUrl}/register`, credentials);
        if (res.status === 201) {
          this.auth = {
            token: res.data.token,
            isAutenticated: true,
          };
          await this.getRole(res.data.token);
        }
      } catch (error) {
        throw error;
      }
    },

    async login(credentials) {
      try {
        const res = await axios.post(`${apiUrl}/login`, credentials);
        if (res.status === 200) {
          this.auth = {
            token: res.data.token,
            isAuthenticated: true,
          };
          await this.getRole(res.data.token);
        }
      } catch (error) {
        console.log("Login error: ", error);
        throw error;
      }
    },

    async getRole(headerToken) {
      try {
        const token = headerToken || this.auth.token;
        const res = await axios.get(`${apiUrl}/me`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.auth.role = res.data.user.role;
        }
      } catch (error) {
        console.log("Failed to get role: ", error);
        throw error;
      }
    },

    async getProfile() {
      try {
        const res = await axios.get(`${apiUrl}/me`, {
          headers: {
            Authorization: `Bearer ${this.auth.token}`,
          },
        });
        if (res.status === 200) {
          this.user = res.data.user;
        }
      } catch (error) {
        console.log("Failed to get profile: ", error);
        throw error;
      }
    },

    async logout() {
      try {
        const res = await axios.delete(`${apiUrl}/logout`, {
          headers: {
            Authorization: `Bearer ${this.auth.token}`,
          },
        });
        if (res.status === 200) {
          this.auth.isAuthenticated = false;
          this.auth.token = "";
          this.auth.role = "";
        }
      } catch (error) {
        throw error;
      }
    },
  },
});
