<script setup>
import BackButton from "@/components/BackButton.vue";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";
import {useFoodStore} from "@/stores/food";
import {useRoute} from "vue-router";

const authStore = useAuthStore();
const foodStore = useFoodStore();

const route = useRoute();

const foodId = Number(route.params.id);

const form = ref({
  name: "",
  description: "",
  category: "",
  imageUrl: "",
  price: null,
});

const foodCategories = [
  "PREDJELO",
  "GLAVNO JELO",
  "DESERT",
  "NAPITAK",
  "PRILOG",
  "SALATA",
  "JUHA",
];

onMounted(async () => {
  if (authStore.auth.role !== 'ADMIN') await router.push('/');
  await foodStore.fetchFoodById(foodId);
  form.value = foodStore.food;
})

const submit = async () => {
  if(form.value.category === "GLAVNO JELO") {
    form.value.category = "GLAVNO_JELO";
  }
  await foodStore.updateFood(foodId, form.value);
  await router.push('/admin/offers');
  window.location.reload();
}
</script>

<template>
  <v-container fluid class="fill-height">
    <v-row class="pb-8">
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3" class="d-flex">
        <BackButton />
      </v-col>
      <v-col cols="10" sm="8" md="6" lg="4"  offset="1" offset-sm="2" offset-md="3" offset-lg="4">
        <v-icon size="8rem" class="text-center text-primary w-100 mb-4">mdi-food</v-icon>
        <h4 class="text-h4 text-center font-weight-medium pb-12">Uredi ponudu</h4>
        <v-form @submit.prevent="submit">
          <v-text-field density="compact" placeholder="Naziv ponude" rounded
                        variant="outlined" v-model="form.name" class="mb-1" append-inner-icon="."/>

          <v-text-field density="compact" placeholder="Opis ponude" rounded
                        variant="outlined" v-model="form.description" class="mb-1" append-inner-icon="."/>

          <v-select :items="foodCategories" variant="outlined" label="Vrsta ponude" v-model="form.category" class="mb-1" rounded/>

<!--          <v-file-input density="compact" label="Odaberite sliku ponude" variant="outlined" rounded
                        v-model="form.image" class="mb-1" />-->

          <v-text-field density="compact" placeholder="Unesite cijenu ponude" variant="outlined" suffix="KM" rounded
                        type="number" step="0.05" v-model="form.price" class="mb-1" />

          <v-btn type="submit" prepend-icon="mdi-plus" block variant="flat" color="primary" size="large" class="mb-8 mt-2" rounded>
            Spremi promjene
          </v-btn>
        </v-form>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>

</style>
