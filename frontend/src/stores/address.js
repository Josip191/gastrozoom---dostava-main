import { defineStore } from "pinia";
import axios from "axios";
import { useAuthStore } from "@/stores/auth";

const apiUrl = 'http://localhost:4000/address';

export const useAddressStore = defineStore('address', {
  state: () => ({
    addresses: [],
    address: null,
  }),

  actions: {
    async fetchAddresses() {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.get(`${apiUrl}/all`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.addresses = res.data;
        }
      } catch (error) {
        console.log("Failed to fetch all addresses: ", error);
        throw error;
      }
    },

    async fetchAddressById(id) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.get(`${apiUrl}/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.address = res.data;
        }
      } catch (error) {
        console.log("Failed to fetch address: ", error);
        throw error;
      }
    },

    async fetchPrimaryAddress() {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.get(`${apiUrl}/primary`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.address = res.data;
        }
      } catch (error) {
        console.log("Failed to fetch primary address: ", error);
        throw error;
      }
    },

    async createAddress(addressData) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.post(`${apiUrl}/create`, addressData, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 201) {
          this.addresses.push(res.data);
        }
      } catch (error) {
        console.log("Failed to create address: ", error);
        throw error;
      }
    },

    async updateAddress(id, addressData) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.put(`${apiUrl}/${id}`, addressData, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          const index = this.addresses.findIndex(address => address.id === id);
          if (index !== -1) {
            this.addresses[index] = res.data;
          }
        }
      } catch (error) {
        console.log("Failed to update address: ", error);
        throw error;
      }
    },

    async deleteAddress(id) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.delete(`${apiUrl}/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.addresses = this.addresses.filter(address => address.id !== id);
        }
      } catch (error) {
        console.log("Failed to delete address: ", error);
        throw error;
      }
    },
  },
});
