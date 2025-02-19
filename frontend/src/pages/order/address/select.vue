<script setup>
import { ref, onMounted } from 'vue';
import { useAddressStore } from '@/stores/address';
import BackButton from "@/components/BackButton.vue";
import {useOrderStore} from "@/stores/order";
import {useBasketStore} from "@/stores/basket";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";

const addressStore = useAddressStore();
const basketStore = useBasketStore();
const orderStore = useOrderStore();
const authStore = useAuthStore();

const primaryAddress = reactive({});
const allAddresses = ref([]);
const selectedAddress = reactive({});
const menuVisible = ref(false);

const setAddresses = () => {
  primaryAddress.value = addressStore.address;
  allAddresses.value = addressStore.addresses;
};

onMounted(async () => {
  if (!authStore.auth.isAuthenticated) await router.push('/login');
  await addressStore.fetchAddresses();
  await addressStore.fetchPrimaryAddress();
  setAddresses();
  selectedAddress.value = primaryAddress.value;
});

const selectAddress = (address) => {
  selectedAddress.value = address;
  menuVisible.value = false;
};

const createOrder = async () => {
  try {
    if (basketStore.basket.basketItems.length === 0) {
      alert('Košarica je prazna');
      return;
    }
    if (!selectedAddress.value) {
      alert('Molimo odaberite adresu');
      return;
    }
    const order = {
      basketItems: basketStore.basket.basketItems,
      addressId: selectedAddress.value.id,
      deliveryPrice: 2.5,
    };
    console.log(order);
    await orderStore.createOrder(order);
    basketStore.clearBasket();
    await router.push('/orders');
    window.location.reload();
  } catch (error) {
    throw error;
  }
};
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton />
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Odaberi adresu</h1>
        </div>
      </v-col>
    </v-row>
    <v-row justify="center" class="pb-4">
      <v-col cols="12" sm="10" md="8" lg="6">
        <v-card class="custom-radius custom-shadow pa-4">
          <v-card-title class="d-flex align-center text-h5 text-sm-h4 text-start mb-4">
            <v-icon class="text-center text-primary mr-2">mdi-map-marker</v-icon>
            Adresa za dostavu
          </v-card-title>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start">
            <span class="font-weight-medium">Naziv ulice:</span> {{ selectedAddress.value?.address }}
          </v-card-text>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start">
            <span class="font-weight-medium">Kućni broj:</span> {{ selectedAddress.value?.addressNumber }}
          </v-card-text>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start">
            <span class="font-weight-medium">Kat:</span> {{ selectedAddress.value?.floorNumber }}
          </v-card-text>
          <v-card-text class="text-subtitle-1 text-sm-h6 text-start">
            <span class="font-weight-medium">Način dostave:</span>
            {{ selectedAddress.value?.isSelectedOnDoor ? 'Dostaviti na vratima' : 'Preuzet ću ja' }}
          </v-card-text>
        </v-card>
        <div class="gap flex-column mt-8 flex-sm-row">
          <v-menu v-model="menuVisible" location="bottom" offset="8">
            <template v-slot:activator="{ props }">
              <v-btn v-bind="props" class="my-2 custom-radius" :width="$vuetify.display.xs ? '100%' : '48%'"
                     color="primary" variant="outlined" append-icon="mdi-chevron-down" size="large">
                Odaberi adresu
              </v-btn>
            </template>
            <v-list rounded="xl" elevation="0" bg-color="primary" variant="flat">
              <v-list-item class="bg-primary" v-for="address in allAddresses" :key="address.id" @click="selectAddress(address)">

                <v-list-item-title>{{ address.address }}</v-list-item-title>
                <v-list-item-subtitle opacity="70%">Kućni broj: {{ address.addressNumber }}, Kat: {{ address.floorNumber }}</v-list-item-subtitle>

              </v-list-item>
            </v-list>
          </v-menu>
          <v-btn class="my-2 custom-radius" :width="$vuetify.display.xs ? '100%' : '48%'" color="primary"
                 variant="flat" @click="createOrder" append-icon="mdi-chevron-right" size="large">
            Naruči
          </v-btn>
        </div>

      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.custom-radius {
  border-radius: 16px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}

.gap {
  display: flex;
  gap: 4%;
}
</style>
