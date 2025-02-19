<script setup>

import BackButton from "@/components/BackButton.vue";
</script>

<template>
  <v-container fluid>
    <v-row class="d-flex align-center py-6" justify="center">
      <v-col cols="12" sm="10" md="10" class="d-flex">
        <BackButton/>
        <div class="d-flex align-center pl-6">
          <h1 class="text-h5 text-md-h4 font-weight-medium">O Projektu</h1>
        </div>
      </v-col>
    </v-row>
    <v-card variant="text" class="py-md-16 my-md-16">
      <v-row justify="center" align="center">
        <v-col cols="12" sm="10" md="4">
          <v-img src="/about.svg" height="30rem" class="custom-radius">
            <template #placeholder>
              <v-icon class="fill-height w-100" size="4rem">mdi-image</v-icon>
            </template>
          </v-img>
        </v-col>
        <v-col cols="12" sm="10" md="6">
          <v-card-text class="text-h6">
            Ovaj projekt je web aplikacija napravljena koristeći moderne tehnologije za frontend i backend. Za frontend
            su korišteni Vuetify i Pinia, dok su za backend korišteni MySQL, Prisma i Express. Aplikacija omogućava
            korisnicima pregled ponuda, prijavu, te pristup različitim funkcionalnostima ovisno o statusu korisnika
            (gost ili prijavljeni korisnik).
          </v-card-text>
        </v-col>
      </v-row>
    </v-card>
    <v-row justify="space-evenly" class="py-16">
      <v-col cols="10" sm="8" md="4" lg="3">
        <v-card class="custom-shadow pb-4" rounded="xl">
          <v-img src="/profile-1.jpg" class="bg-grey-lighten-2 ma-4 custom-radius aspect-ratio">
            <template #placeholder>
              <v-icon class="fill-height w-100" size="4rem">mdi-image</v-icon>
            </template>
          </v-img>
          <v-card-title class="text-h6 mx-3">Luka Raič</v-card-title>
          <v-card-text class="text-subtitle-1 mx-3">Rođen 13. rujna 2001. Živim u Mostaru. Student sam treće godine
            informatike na FPMOZ-u u Mostaru.</v-card-text>
        </v-card>
      </v-col>
      <v-col cols="10" sm="8" md="4" lg="3">
        <v-card class="custom-shadow pb-4" rounded="xl">
          <v-img src="/profile-2.jpg" class="bg-grey-lighten-2 ma-4 custom-radius aspect-ratio">
            <template #placeholder>
              <v-icon class="fill-height w-100" size="4rem">mdi-image</v-icon>
            </template>
          </v-img>
          <v-card-title class="text-h6 mx-3">Josip Pehar</v-card-title>
          <v-card-text class="text-subtitle-1 mx-3">Rođen 23. rujna 2001. godine. Živim u Čitluku. Student sam treće godine
            informatike na FPMOZ-u u Mostaru.</v-card-text>
        </v-card>
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

.aspect-ratio {
  aspect-ratio: 1/1;
}
</style>
