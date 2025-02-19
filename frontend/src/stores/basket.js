import {useLocalStorage} from "@vueuse/core";
import {useFoodStore} from "@/stores/food";
import {defineStore} from "pinia";

export const useBasketStore = defineStore('basket', {
  state: () => ({
    basket: {
      basketItems: useLocalStorage('basketItems', []),
      foods: [],
      isFoodInBasket: false,
    }
  }),

  actions: {
    addFoodToBasket(foodId, quantity = 1) {
      this.basket.basketItems.push({ foodId: foodId, quantity: quantity});
      this.saveBasket();
    },

    removeFoodFromBasket(foodId) {
      this.basket.basketItems = this.basket.basketItems.filter(item => item.foodId !== foodId);
      this.saveBasket();
    },

    clearBasket() {
      this.basket.basketItems = [];
      this.saveBasket();
    },

    updateFoodQuantity(foodId, newQuantity) {
      const foodIndex = this.basket.basketItems.findIndex(item => item.foodId === foodId);
      console.log(foodId)
      console.log(foodIndex)
      if (foodIndex !== -1) {
        this.basket.basketItems[foodIndex].quantity = newQuantity;
      }
      this.saveBasket();
      console.log(this.basket.basketItems)
    },

    saveBasket() {
      useLocalStorage('basketItems', this.basket.basketItems);
    },

    checkIsFoodInBasket(foodId) {
      this.basket.isFoodInBasket = this.basket.basketItems.length > 0 && this.basket.basketItems.some(item => item.foodId === foodId);
    },

    getFoodQuantity(foodId) {
      const food = this.basket.basketItems.find(item => Number(item.foodId) === foodId);
      return food ? food.quantity : 1;
    },

    async fetchBasketFoods() {
      const foodStore = useFoodStore();
      await foodStore.fetchFoods();

      this.basket.foods = foodStore.foods.filter(food =>
        this.basket.basketItems.some(item => Number(item.foodId) === food.id)
      );
    },
  },
})
