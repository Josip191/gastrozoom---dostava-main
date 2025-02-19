<script setup>

import BackButton from "@/components/BackButton.vue";
import {useFoodStore} from "@/stores/food";
import {useRoute} from "vue-router";
import {useBasketStore} from "@/stores/basket";
import {ref} from "vue";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";

const route = useRoute();
const foodId = Number(route.params.id);

const food = ref({});
const quantity = ref(1);
const inputWidth = ref(42);

const foodStore = useFoodStore();
const basketStore = useBasketStore();
const authStore = useAuthStore();

onMounted(
  async () => {
    await foodStore.fetchFoodById(foodId);
    food.value = foodStore.food;
    basketStore.checkIsFoodInBasket(foodId);
    quantity.value = basketStore.getFoodQuantity(food.value.id);
  }
);

const updateWidth = () => {
  const inputLength = quantity.value.toString().length;
  inputWidth.value = Math.max((inputLength + 1) * 10 + 20, 42);
};

const onQuantityChange = () => {
  updateWidth();
  if (quantity.value < 1) {
    quantity.value = 1;
  }
  if (basketStore.basket.isFoodInBasket) {
    basketStore.updateFoodQuantity(foodId, quantity.value);
  }
};

const increaseQuantity = () => {
  quantity.value += 1;
  onQuantityChange();
};

const decreaseQuantity = () => {
  if (quantity.value > 1) {
    quantity.value -= 1;
    onQuantityChange();
  }
};

const addToBasket = async () => {
  if (!authStore.auth.isAuthenticated) {
    await router.push('/login');
    return;
  }
  basketStore.addFoodToBasket(foodId, quantity.value);
  basketStore.checkIsFoodInBasket(foodId);
};

const orderNow = async () => {
  if (!authStore.auth.isAuthenticated) {
    await router.push('/login');
    return;
  }
  if (!basketStore.basket.isFoodInBasket) {
    basketStore.addFoodToBasket(foodId, quantity.value);
  }
  await router.push('/order');
  window.location.reload();
};

watch(
  () => basketStore.basket.basketItems,
  async () => {
    basketStore.checkIsFoodInBasket(foodId);
    quantity.value = basketStore.getFoodQuantity(foodId);
  }
);

</script>

<template>
  <v-container fluid class="fill-height">
    <v-row class="pt-2 pb-16">
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3">
        <BackButton />
      </v-col>
      <v-col cols="12" sm="10" md="6" lg="4" offset-sm="1" offset-md="3" offset-lg="4">
        <v-card class="py-2 custom-shadow" variant="text" rounded="xl">
          <v-card-item class="">
            <v-img :src="food.imageUrl" class="bg-grey-lighten-2 align-center custom-radius aspect-ratio" width="100%">
              <v-icon class="text-center w-100">mdi-image</v-icon>
            </v-img>
          </v-card-item>
          <v-card-title class="mx-4 text-h4 text-start text-wrap">{{ food.name }}</v-card-title>
          <v-card-text class="mx-4 text-subtitle-1">{{ food.description }}</v-card-text>

          <v-card-actions class="d-flex justify-between">
            <div class="d-inline-flex align-center ml-6">
              <v-btn icon="mdi-minus" class="custom-radius" color="primary" variant="tonal" size="small"
                     @click="decreaseQuantity"/>
              <v-text-field density="compact" variant="plain" type="number" step="1" min="1"
                            v-model="quantity" hide-spin-buttons single-line min-width="42px"
                            :style="{ maxWidth: `${inputWidth}px` }"
                            class="font-weight-medium text-center px-4 mt-5"/>
              <v-btn icon="mdi-plus" class="mr-6 custom-radius" color="primary" variant="flat" size="small"
                     @click="increaseQuantity"/>
            </div>

            <v-card-text class="mx-4 text-end text-h5 font-weight-medium text-primary">Cijena: {{ food.price }} KM</v-card-text>
          </v-card-actions>
          <v-card-actions class="d-flex flex-column flex-sm-row justify-space-evenly">
            <v-btn color="primary" variant="tonal" prepend-icon="mdi-basket" min-width="48%" width="98%"
                   class="custom-radius w-sm-auto" @click="orderNow" size="large"
            >
              Naruči odmah
            </v-btn>
            <v-btn v-if="!basketStore.basket.isFoodInBasket" color="primary" variant="flat" prepend-icon="mdi-basket-plus"
                   min-width="48%" width="98%" class="custom-radius w-sm-auto" @click="addToBasket" size="large"
            >
              Dodaj u narudžbu
            </v-btn>
            <v-btn v-if="basketStore.basket.isFoodInBasket" color="primary" variant="outlined"
                   prepend-icon="mdi-basket-remove-outline" min-width="48%" width="98%"
                   class="custom-radius w-sm-auto" @click="basketStore.removeFoodFromBasket(food.id)" size="large"
            >
              Ukloni iz narudžbe
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.aspect-ratio {
  aspect-ratio: 16 / 9;
}

.custom-radius {
  border-radius: 16px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
