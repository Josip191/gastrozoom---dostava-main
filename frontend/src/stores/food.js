import { defineStore } from "pinia";
import axios from "axios";
import { useAuthStore } from "@/stores/auth";

const apiUrl = "http://gastrozoom.studenti.sumit.ba/food";

export const useFoodStore = defineStore("food", {
  state: () => ({
    foods: [],
    food: null,
  }),

  actions: {
    async fetchFoods() {
      try {
        const res = await axios.get(`${apiUrl}/all`);
        if (res.status === 200) {
          this.foods = res.data;
        }
      } catch (error) {
        console.log("Failed to fetch foods: ", error);
        throw error;
      }
    },

    async fetchFoodById(id) {
      try {
        const res = await axios.get(`${apiUrl}/${id}`);
        if (res.status === 200) {
          this.food = res.data;
        }
      } catch (error) {
        console.log("Failed to fetch food: ", error);
        throw error;
      }
    },

    async createFood(foodData) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.post(`${apiUrl}/create`, foodData, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 201) {
          this.foods.push(res.data);
        }
      } catch (error) {
        console.log("Failed to create food: ", error);
        throw error;
      }
    },

    async updateFood(id, foodData) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        await axios.put(`${apiUrl}/${id}`, foodData, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } catch (error) {
        console.log("Failed to update food: ", error);
        throw error;
      }
    },

    async deleteFood(id) {
      try {
        const authStore = useAuthStore();
        const token = authStore.auth.token;
        const res = await axios.delete(`${apiUrl}/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status === 200) {
          this.foods = this.foods.filter((food) => food.id !== id);
        }
      } catch (error) {
        console.log("Failed to delete food: ", error);
        throw error;
      }
    },
  },
});
