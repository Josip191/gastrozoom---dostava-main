<template>
  <v-container fluid class="mt-6 mb-16">
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="8" lg="6" class="d-flex">
        <BackButton />
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">Ponude</h1>
        </div>
      </v-col>
    </v-row>
    <v-row class="d-flex align-center my-4 mx-2 justify-space-between">
      <v-col class="d-flex justify-end align-center" cols="12" sm="8" lg="6" offset-sm="2" offset-lg="3">
        <v-text-field
          v-model="search"
          class="custom-text-field elevation-0 bg-secondary rounded-xl pl-8 pr-4 pb-2"
          append-inner-icon="mdi-magnify"
          label="Pretraži"
          variant="plain"
          density="comfortable"
          clearable
          rounded
          hide-details
        />
        <v-btn icon="mdi-plus" class="ml-4 custom-radius" variant="flat" color="primary" to="/admin/offers/add"/>
      </v-col>
      <v-col class="12" sm="10" lg="8" offset-sm="1" offset-lg="2">
        <v-data-table :headers="headers" :items="foods" :search="search" multi-sort
                      items-per-page-text="Broj stavki po stranici" :items-per-page="10">

          <template v-slot:item.name="{ item }">
            <div class="truncate-name-column">{{ item.name }}</div>
          </template>
          <template v-slot:item.updatedAt="{ item }">
            <div class="truncate-date-column">{{ formatDate(item.updatedAt) }}</div>
          </template>
          <template v-slot:item.createdAt="{ item }">
            <div class="truncate-date-column">{{ formatDate(item.createdAt) }}</div>
          </template>
          <template v-slot:item.price="{ item }">
            <div class="truncate-name-column">{{ item.price }} KM</div>
          </template>

          <template v-slot:no-data>
            <p>Nema ponuda</p>
          </template>
          <template v-slot:item.actions="{ item }">
            <v-btn icon="mdi-pencil" variant="outlined" color="primary" size="small"
                   :to="`/admin/offers/${item.id}/edit`" class="ma-1 custom-radius" />
            <v-btn icon="mdi-delete" variant="flat" color="primary" size="small"
                   @click="async () => await deleteFood(item.id)" class="ma-1 custom-radius" />
          </template>
        </v-data-table>
      </v-col>
    </v-row>


  </v-container>
</template>

<script setup>

import BackButton from "@/components/BackButton.vue";
import router from "@/router";
import {useAuthStore} from "@/stores/auth";
import {useFoodStore} from "@/stores/food";

const foods = ref([]);
const search = ref("");

const headers = [
  { title: "ID", text: "ID", value: "id", sortable: true },
  { title: "Naziv", text: "Naziv", value: "name", sortable: true },
  { title: "Cijena", text: "Cijena", value: "price", sortable: true },
  {
    title: "Akcije",
    text: "Akcije",
    value: "actions",
    sortable: false,
    align: "center",
  },
];

const authStore = useAuthStore();
const foodStore = useFoodStore();

const deleteFood = async (foodId) => {
  await foodStore.deleteFood(foodId);
  await foodStore.fetchFoods();
  foods.value = foodStore.foods;
};

onMounted(async () => {
  if (authStore.auth.role !== 'ADMIN') await router.push('/');
  try {
    await foodStore.fetchFoods();
    foods.value = foodStore.foods;
  } catch (e) {
    console.error(e);
  }
})
</script>

<style scoped>
.custom-radius {
  border-radius: 16px;
}

.custom-radius {
  border-radius: 16px;
}

.truncate-name-column {
  max-width: 300px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.truncate-date-column {
  width: 81px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

@media (min-width: 601px) and (max-width: 960px) {
  .truncate-name-column {
    max-width: 150px;
  }
}

@media (min-width: 961px) and (max-width: 1264px) {
  .truncate-name-column {
    max-width: 200px;
  }
}
</style>
