<script setup>
import BackButton from "@/components/BackButton.vue";
import { ref } from "vue";
import OrderFoodCard from "@/components/OrderFoodCard.vue";
import {useBasketStore} from "@/stores/basket";
import {useAddressStore} from "@/stores/address";
import {useRouter} from "vue-router";
import {useAuthStore} from "@/stores/auth";

const router = useRouter();

const deliveryPrice = ref(2.5);
const foods = ref([]);

const basketStore = useBasketStore();
const addressStore = useAddressStore();
const authStore = useAuthStore();

const priceWithoutDelivery = computed(() => {
  return foods.value.reduce((total, food) => {
    return total += food.price * basketStore.getFoodQuantity(food.id);
  }, 0);
});

const totalPrice = computed(() => {
  return priceWithoutDelivery.value + deliveryPrice.value;
});

const createOrder = async () => {
  try {
    await addressStore.fetchAddresses();
    if (addressStore.addresses.length > 0) {
      await router.push('/order/address/select');
      window.location.reload();
    } else {
      await router.push('/order/address/add');
      window.location.reload();
    }
  } catch (error) {
      throw error;
  }
};

onMounted(async () => {
  if (!authStore.auth.isAuthenticated) await router.push('/login');
  await basketStore.fetchBasketFoods();
  foods.value = basketStore.basket.foods;
  console.log(foods.value);
});

const removeFoodFromBasket = async (foodId) => {
  await basketStore.removeFoodFromBasket(foodId);
};

watch(
  () => basketStore.basket.basketItems,
  async () => {
    await basketStore.fetchBasketFoods();
    foods.value = basketStore.basket.foods;
  }
);
</script>

<template>
  <v-container fluid class="d-flex flex-column"
               :style="basketStore.basket.basketItems.length > 0 ? 'height: calc(100vh - 64px)' : ''"
  >
    <v-row class="d-flex align-center py-4" justify="center">
      <v-col cols="11" md="8" lg="6" class="d-flex">
        <BackButton />
        <div class="d-flex align-center pl-6">
          <h1 class="text-h4 font-weight-medium">Detalji narudžbe</h1>
        </div>
      </v-col>
    </v-row>

    <v-row v-if="foods.length === 0" justify="center">
      <v-col cols="11" md="8" lg="6">
        <h3 class="text-center text-primary text-h3">Korpa je prazna</h3>
      </v-col>
    </v-row>

    <v-row v-for="food in foods" justify="center">
      <v-col :key="food.id" cols="11" md="8" lg="6">
        <OrderFoodCard :id="food.id" :title="food.name" :price="food.price" :src="food.imageUrl"
                       :removeFoodFromBasket="removeFoodFromBasket"
        />
      </v-col>
    </v-row>

    <v-row v-if="basketStore.basket.basketItems.length > 0" justify="center" align="end" class="pt-1">
      <v-col cols="11" md="8" lg="6">
        <v-card class="bg-primary d-flex flex-column pa-3" rounded="xl">
          <v-card-text class=" d-flex justify-space-between">
            <span>Iznos:</span>
            <span>{{ priceWithoutDelivery }} KM</span>
          </v-card-text>
          <v-card-text class=" d-flex justify-space-between">
            <span>Dostava:</span>
            <span>{{ deliveryPrice }} KM</span>
          </v-card-text>
          <v-divider opacity="60%" class="text-white"></v-divider>
          <v-card-text class=" d-flex justify-space-between">
            <span>Za platiti:</span>
            <span>{{ totalPrice }} KM</span>
          </v-card-text>
          <v-btn class="mx-2 mb-2 text-primary" variant="flat" rounded size="x-large" @click="createOrder">Gotovo</v-btn>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
</style>
