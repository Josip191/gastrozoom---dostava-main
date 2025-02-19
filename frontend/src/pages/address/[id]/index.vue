<script setup>
import BackButton from "@/components/BackButton.vue";
import {useAddressStore} from "@/stores/address";
import {useRoute} from "vue-router";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";

const route = useRoute();
const address = ref({});
const addressId = route.params.id;

const addressStore = useAddressStore();
const authStore = useAuthStore();

onMounted(async () => {
  if (!authStore.auth.isAuthenticated) await router.push('/login');
  await addressStore.fetchAddressById(addressId);
  await addressStore.fetchAddresses();
  address.value = addressStore.address;
  console.log(address.value);
});

watch(
  () => address.value.isPrimary,
  (newValue, oldValue) => {
    if (newValue !== oldValue) {
      addressStore.updateAddress(addressId, address.value);
    }
  }
)
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton />
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Moja adresa</h1>
        </div>
      </v-col>
    </v-row>
    <v-row>
      <v-col cols="10" sm="8" md="6" lg="4" offset="1" offset-sm="2" offset-md="3" offset-lg="4">
        <v-card variant="text">
          <v-icon size="8rem" class="text-center text-primary w-100 mb-10">mdi-map-marker</v-icon>
          <v-card-text>
            <h6 class="text-h6 font-weight-bold">Naziv ulice</h6>
            <h5 class="text-h5">{{ address.address }}</h5>
          </v-card-text>

          <v-row>
            <v-col cols="6">
              <v-card-text>
                <h6 class="text-h6 font-weight-bold">Kućni broj</h6>
                <h5 class="text-h5">{{ address.addressNumber }}</h5>
              </v-card-text>
            </v-col>
            <v-col cols="6">
              <v-card-text>
                <h6 class="text-h6 font-weight-bold">Kat</h6>
                <h5 class="text-h5">{{ address.floorNumber }}</h5>
              </v-card-text>
            </v-col>
          </v-row>

          <v-card-text>
            <h6 class="text-h6 font-weight-bold">Način dostave</h6>
            <h5 class="text-h5">{{ address.isSelectedOnDoor ? 'Dostaviti na vratima' : 'Preuzet ću ja' }}</h5>
          </v-card-text>

          <div v-if="addressStore.addresses.length > 1" class="d-flex justify-space-between mx-2 align-center">
            <span>Postavi kao zadanu adresu</span>
            <v-switch color="primary" class="ml-2 mt-6" v-model="address.isPrimary"/>
          </div>

          <v-btn type="submit" :to="`/address/${addressId}/edit`" prepend-icon="mdi-pencil" block variant="flat" color="primary" size="large" class="mb-8 mt-4" rounded>
            Uredi adresu
          </v-btn>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>

</style>
