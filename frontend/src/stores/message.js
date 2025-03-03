import { defineStore } from "pinia";
import axios from "axios";
import { useAuthStore } from "@/stores/auth";

const apiUrl = "http://gastrozoom.studenti.sumit.ba/message";

export const useMessageStore = defineStore("message", {
  state: () => ({
    messages: [],
    message: null,
  }),

  actions: {
    async fetchMessages() {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.get(`${apiUrl}/all`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.messages = res.data;
        }
      } catch (error) {
        console.log("Failed to fetch messages: ", error);
        throw error;
      }
    },

    async createMessage(messageData) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.post(`${apiUrl}/create`, messageData, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 201) {
          this.messages.push(res.data);
        }
      } catch (error) {
        console.log("Failed to create message: ", error);
        throw error;
      }
    },

    async deleteMessage(id) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.delete(`${apiUrl}/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.messages = this.messages.filter((message) => message.id !== id);
        }
      } catch (error) {
        console.log("Failed to delete message: ", error);
        throw error;
      }
    },
  },
});
