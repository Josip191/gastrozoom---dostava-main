<script setup>
import BackButton from "@/components/BackButton.vue";
import {useAddressStore} from "@/stores/address";
import router from "@/router";
import {ref} from "vue";
import {useAuthStore} from "@/stores/auth";

const form = ref({
  address: "",
  addressNumber: "",
  floorNumber: "",
  isPrimary: false,
  isSelectedOnDoor: false,
});

const alertMessage = ref('');
const alertVisible = ref(false);

const addressStore = useAddressStore();
const authStore = useAuthStore();

onMounted(async () => {
  if (!authStore.auth.isAuthenticated) await router.push('/login');
  await addressStore.fetchAddresses();
});

const submit = async () => {
  try {
    await addressStore.createAddress(form.value);
    await router.push('/order/address/select');
    window.location.reload();
  } catch (error) {
    console.log(error);
    if (error.response.status >= 400) {
      console.log(error.response.data.error)
      alertMessage.value = error.response.data.error;
      alertVisible.value = true;
    }
  }
};
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="8" lg="6" class="d-flex">
        <BackButton />
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Dodaj adresu</h1>
        </div>
      </v-col>
    </v-row>
    <v-row>
      <v-col cols="10" sm="8" md="6" lg="4"  offset="1" offset-sm="2" offset-md="3" offset-lg="4">
        <v-icon size="8rem" class="text-center text-primary w-100 mb-16">mdi-map-marker-plus</v-icon>
        <v-form @submit.prevent="submit">
          <v-text-field density="compact" placeholder="Naziv ulice" prepend-inner-icon="mdi-home-city" rounded
                        variant="outlined" v-model="form.address" class="mb-1" append-inner-icon="."/>

          <v-row>
            <v-col cols="6">
              <v-text-field density="compact" placeholder="Kućni broj" rounded
                            variant="outlined" v-model="form.addressNumber" class="mb-1" append-inner-icon="."/>
            </v-col>
            <v-col cols="6">
              <v-text-field density="compact" placeholder="Kat" rounded
                            variant="outlined" v-model="form.floorNumber" class="mb-1" append-inner-icon="."/>
            </v-col>
          </v-row>

          <div class="d-flex flex-column flex-sm-row justify-space-evenly">
            <v-btn color="primary" :active="!form.isSelectedOnDoor" @click="form.isSelectedOnDoor = false" variant="outlined"
                   min-width="48%" width="98%" rounded class="mx-1 my-2 w-sm-auto"
            >
              Preuzet ću ja
            </v-btn>
            <v-btn color="primary" :active="form.isSelectedOnDoor" @click="form.isSelectedOnDoor = true" variant="outlined"
                   min-width="48%" width="98%" rounded class="mx-1 my-2 w-sm-auto"
            >
              Dostaviti na vrata
            </v-btn>
          </div>

          <div v-if="addressStore.addresses.length > 0" class="d-flex justify-space-between mx-2 align-center">
            <span>Postavi kao zadanu adresu</span>
            <v-switch color="primary" class="ml-2 mt-6" v-model="form.isPrimary"/>
          </div>

          <v-alert v-model="alertVisible" density="compact" variant="tonal" type="error" class="mb-4"
                   rounded="xl">
            {{ alertMessage }}
          </v-alert>

          <v-btn type="submit" prepend-icon="mdi-plus" block variant="flat" color="primary" size="large" class="mb-8 mt-2" rounded>
            Dodaj adresu
          </v-btn>
        </v-form>

      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>

</style>
